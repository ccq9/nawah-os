#!/usr/bin/env python3
"""TST-M2-MUTANTS (REQ-M2-014): seeded-defect mutation testing of the kernel's arch/, mm/ and
sync code against the M1/M2 guest suites.

Each mutant is one deliberate defect (a textual patch that must match exactly once). The runner
works in a detached git worktree of HEAD so the real checkout, its build/ directory and the
evidence records are never touched: evidence of the mutant runs goes to a scratch directory
(NAWAH_SCRATCH_EVIDENCE) and tools/project.py attaches nothing in that mode.

For each mutant: apply, build only the artifacts its killer tests need, run those tests
(`project.py boot` for TST-M1-BOOT, `project.py test --only` for M2 cases). A mutant is
  killed   - at least one killer test FAILs (or times out) ;
  survived - every killer test PASSes; the whole M1+M2 suites are then run before the verdict ;
  invalid  - the mutant does not compile (excluded from the ratio; a defect that cannot build is
             not a defect the suite had to catch).
PASS = kill ratio >= 0.95 over valid mutants. `--check` only applies/reverts the patches and
type-checks them on the host target (what this sandbox can do without the UEFI toolchain).
"""
import argparse, json, os, subprocess, sys, tempfile, time, shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
THRESHOLD = 0.95

# (id, file, old, new, killers, note)
MUTANTS = [
    ("M01", "kernel/src/arch/x86_64/gdt.rs",
     "            .write_unaligned(df.0 + df.1);\n    }\n}",
     "            .write_unaligned(df.0);\n    }\n}",
     ["TST-M2-EXC-DF"], "IST1 points at the base of the #DF stack instead of its top"),
    ("M02", "kernel/src/arch/x86_64/idt.rs",
     "        let ist = if vector == DOUBLE_FAULT_VECTOR {\n            DOUBLE_FAULT_IST\n        } else {\n            0\n        };",
     "        let ist = 0 * (vector == DOUBLE_FAULT_VECTOR) as u8;",
     ["TST-M2-IDT-LAYOUT", "TST-M2-EXC-DF"], "#DF gate loses its IST (the const assertion on Gate::interrupt still holds)"),
    ("M03", "kernel/src/arch/x86_64/trap.rs",
     "    add rsp, 16\n    iretq", "    add rsp, 8\n    iretq",
     ["TST-M2-EXC-BP"], "error code left on the stack before iretq"),
    ("M04", "kernel/src/arch/x86_64/trap.rs",
     "    if depth > MAX_NESTING {\n        fatal(frame.vector);\n    }\n    if depth == MAX_NESTING {",
     "    if depth > MAX_NESTING + 1000 {\n        fatal(frame.vector);\n    }\n    if depth == MAX_NESTING + 1000 {",
     ["TST-M2-EXC-NESTED"], "nesting limit effectively removed"),
    ("M05", "kernel/src/mm/pmm.rs",
     "            p.set_bit(frame, true);\n            p.free -= 1;", "            p.set_bit(frame, true);",
     ["TST-M2-PMM-COUNTS"], "free counter not decremented on allocation"),
    ("M06", "kernel/src/mm/pmm.rs",
     "    if !p.get_bit(f) {\n        return Err(PmmError::NotAllocated);\n    }", "",
     ["TST-M2-PMM-DOUBLE-FREE"], "double-free detection removed"),
    ("M07", "kernel/src/mm/pmm.rs",
     "const LOW_RESERVED: u64 = 1 << 20; // 1 MiB", "const LOW_RESERVED: u64 = 0; // 1 MiB",
     ["TST-M2-PMM-COUNTS", "TST-M2-PMM-DOUBLE-FREE"], "first MiB handed out"),
    # Removing enable_wp()/enable_nxe() was equivalent on this firmware: OVMF enters the kernel
    # with CR0.WP = 1 and IA32_EFER.NXE = 1 already (mutation run 39098959577). vmm_wp now clears
    # WP before relying on the kernel's enable_wp, so M08 is detectable; for NX the detectable
    # defect is a writable section mapped executable (M09).
    ("M08", "kernel/src/arch/x86_64/paging.rs",
     "const CR0_WP: u64 = 1 << 16;", "const CR0_WP: u64 = 0;",
     ["TST-M2-VMM-WP", "TST-M2-VMM-SWITCH"], "enable_wp a no-op (WP bit constant zeroed); the test clears WP first, so firmware state cannot mask it"),
    ("M09", "kernel/src/mm/vmm.rs",
     "            rw += 1;\n            WRITE | NX", "            rw += 1;\n            WRITE",
     ["TST-M2-VMM-NX", "TST-M2-VMM-SWITCH"], ".data/.bss executable (NX dropped)"),
    ("M10", "kernel/src/mm/vmm.rs",
     "    space.map_range(base, base, hdr_len, NX)?;", "    space.map_range(base, base, hdr_len, WRITE | NX)?;",
     ["TST-M2-VMM-SWITCH"], "image headers writable"),
    ("M11", "kernel/src/mm/vmm.rs",
     "            0 // present, read-only, executable", "            WRITE",
     ["TST-M2-VMM-WP", "TST-M2-VMM-SWITCH"], ".text writable"),
    ("M12", "kernel/src/mm/vmm.rs",
     "        let mut lo = start.max(PAGE_4K);", "        let mut lo = start;",
     ["TST-M2-VMM-SWITCH"], "null page identity-mapped"),
    ("M13", "kernel/src/mm/vmm.rs",
     "    let base = guard + PAGE_4K;", "    let base = guard;",
     ["TST-M2-VMM-SWITCH"], "guard page mapped as stack"),
    ("M14", "kernel/src/mm/vmm.rs",
     "    let reclaimed_frames = pmm::reclaim_boot_services(bi, (image_base, image_end));",
     "    let reclaimed_frames = 0 * image_end;",
     ["TST-M2-VMM-SWITCH"], "boot-services memory never reclaimed"),
    ("M15", "kernel/src/arch/x86_64/apic.rs",
     "pub fn eoi() {\n    write(REG_EOI, 0);\n}", "pub fn eoi() {}",
     ["TST-M2-IRQ-EOI", "TST-M2-TIMER-TICKS"], "EOI never written"),
    ("M16", "kernel/src/arch/x86_64/apic.rs",
     "    write(REG_LVT_TIMER, u32::from(vector) | LVT_TIMER_PERIODIC);", "    write(REG_LVT_TIMER, u32::from(vector));",
     ["TST-M2-TIMER-TICKS"], "timer one-shot instead of periodic"),
    ("M17", "kernel/src/arch/x86_64/apic.rs",
     "    elapsed * 100\n}", "    elapsed * 10\n}",
     ["TST-M2-TIMER-TICKS"], "calibration off by 10x"),
    ("M18", "kernel/src/arch/x86_64/apic.rs",
     "    write(REG_SVR, SVR_ENABLE | u32::from(spurious_vector));", "    write(REG_SVR, SVR_ENABLE | 0xFE);",
     ["TST-M2-SPURIOUS"], "wrong spurious vector programmed"),
    ("M19", "kernel/src/arch/x86_64/irq.rs",
     "    apic::eoi();\n    DEPTH.fetch_sub(1, Ordering::Relaxed);", "    apic::eoi();",
     ["TST-M2-TIMER-TICKS", "TST-M2-IRQ-EOI"], "depth counter never decremented"),
    ("M20", "kernel/src/arch/x86_64/pic.rs",
     "        outb(MASTER_DATA, 0xFF);\n        outb(SLAVE_DATA, 0xFF);", "        outb(MASTER_DATA, 0xFE);\n        outb(SLAVE_DATA, 0xFF);",
     ["TST-M1-BOOT"], "IRQ0 left unmasked on the PIC"),
    ("M21", "kernel/src/sync.rs",
     "        self.lock.holder.store(FREE, Ordering::Release);\n        arch::interrupts::restore(self.interrupts_were_enabled);",
     "        self.lock.holder.store(FREE, Ordering::Release);",
     ["TST-M2-LOCK-IRQSAVE"], "IF not restored when the guard drops"),
    ("M22", "kernel/src/sync.rs",
     "        let interrupts_were_enabled = arch::interrupts::save_and_disable();\n        let me = Self::me();",
     "        let interrupts_were_enabled = arch::interrupts::enabled();\n        let me = Self::me();",
     ["TST-M2-LOCK-IRQSAVE"], "lock taken without disabling interrupts"),
    ("M23", "kernel/src/sync.rs",
     "                Err(holder) if holder == me => {", "                Err(holder) if holder == me + 1000 => {",
     ["TST-M2-LOCK-REENTRY"], "re-entry detection removed (hangs; killed by timeout)"),
    ("M24", "kernel/src/arch/x86_64/acpi.rs",
     "    if !sums_to_zero(rsdp, 20) {", "    if sums_to_zero(rsdp, 20) {",
     ["TST-M1-BOOT", "TST-M2-VMM-SWITCH"], "RSDP checksum test inverted"),
    ("M25", "kernel/src/arch/x86_64/acpi.rs",
     "            1 if slen >= 12 => {", "            1 if slen >= 1200 => {",
     ["TST-M1-BOOT"], "I/O APIC entries ignored"),
    ("M26", "kernel/src/arch/x86_64/gdt.rs",
     "    if within(df.0, df.1) || within(DF_STACK.get() as u64, DF_STACK_SIZE as u64) {\n        \"df\"",
     "    if within(df.0, 0) {\n        \"df\"",
     ["TST-M2-EXC-DF", "TST-M2-VMM-GUARD"], "stack diagnostics never name the #DF stack"),
    ("M27", "kernel/src/boot/stub.rs",
     "            .or_else(|| efi::find_configuration_table(st, &efi::ACPI_10_TABLE_GUID))\n            .unwrap_or(0)",
     "            .map(|_| 0u64)\n            .unwrap_or(0)",
     ["TST-M1-BOOT"], "RSDP never handed to the kernel"),
    ("M28", "kernel/src/arch/x86_64/ioapic.rs",
     "        write(base, low, read(base, low) | REDIR_MASKED);", "        write(base, low, read(base, low) & !REDIR_MASKED);",
     ["TST-M1-BOOT"], "I/O APIC entries unmasked instead of masked"),
    ("M29", "kernel/src/arch/x86_64/trap.rs",
     "    if frame.vector == BREAKPOINT {\n        NESTING.fetch_sub(1, Ordering::Relaxed);\n        return;\n    }", "",
     ["TST-M2-EXC-BP"], "#BP made fatal"),
]

# Applications first (WP-17): the kernel embeds them through NAWAH_APPS_DIR (kernel/build.rs).
APPS_STEP = ["cargo", "build", "--profile", "app", "--offline", "--manifest-path", "user/apps/hello/Cargo.toml",
             "--target", "x86_64-unknown-none", "--target-dir", "build/pc-qemu/cargo-user"]
APPS_OUT = "build/pc-qemu/cargo-user/x86_64-unknown-none/app/hello"
KTEST_STEP = ["cargo", "build", "--profile", "ktest", "--offline", "--manifest-path", "kernel/Cargo.toml",
              "--target", "x86_64-unknown-uefi", "--target-dir", "build/pc-qemu/cargo-ktest", "--features", "ktest"]
KTEST_OUT = "build/pc-qemu/cargo-ktest/x86_64-unknown-uefi/ktest/nawah-kernel.efi"
RELEASE_STEP = ["cargo", "build", "--release", "--offline", "--manifest-path", "kernel/Cargo.toml",
                "--target", "x86_64-unknown-uefi", "--target-dir", "build/pc-qemu/cargo"]
RELEASE_OUT = "build/pc-qemu/cargo/x86_64-unknown-uefi/release/nawah-kernel.efi"
NEG_STEP = ["cargo", "build", "--release", "--offline", "--manifest-path", "kernel/Cargo.toml",
            "--target", "x86_64-unknown-uefi", "--target-dir", "build/pc-qemu/cargo-neg", "--features", "inject_ebs_fail"]
NEG_OUT = "build/pc-qemu/cargo-neg/x86_64-unknown-uefi/release/nawah-kernel.efi"


def sh(cmd, cwd, env=None, timeout=1800):
    return subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)


def apply(wt: Path, m) -> None:
    mid, rel, old, new, _, _ = m
    p = wt / rel
    s = p.read_text(encoding="utf-8")
    n = s.count(old)
    if n != 1:
        raise RuntimeError(f"{mid}: pattern occurs {n} times in {rel} (must be exactly once)")
    p.write_text(s.replace(old, new), encoding="utf-8")


def reset(wt: Path) -> None:
    subprocess.run(["git", "checkout", "-q", "--", "kernel"], cwd=wt, check=True)


def suite_of(target, test_id):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    for suite, cases in t["suites"].items():
        if any(c["id"] == test_id for c in cases):
            return suite
    return None


def run_killers(wt: Path, env, target, killers):
    """Returns (killed_by: list, results: {test_id: PASS|FAIL|SKIPPED}). Every case runs through
    its suite entry (the strong oracle); a missing artifact (exit 20) is SKIPPED, never a kill."""
    results = {}
    pyproj = ["python3", str(wt / "tools" / "project.py")]
    for tid in killers:
        suite = suite_of(target, tid)
        r = sh(pyproj + ["test", "--target", target, "--suite", suite, "--only", tid], wt, env)
        results[tid] = "PASS" if r.returncode == 0 else ("SKIPPED" if r.returncode == 20 or "no artifact" in r.stdout else "FAIL")
    return [t for t, v in results.items() if v == "FAIL"], results


def all_cases(target):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    ids = ["TST-M1-BOOT"]
    for cases in t["suites"].values():
        ids += [c["id"] for c in cases if c["id"] not in ("TST-M1-BOOT",)]
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="pc-qemu")
    ap.add_argument("--report", default="build/mutants-report.json")
    ap.add_argument("--only", help="comma-separated mutant ids")
    ap.add_argument("--check", action="store_true", help="apply/revert each patch and cargo check on the host target only")
    a = ap.parse_args()
    mutants = [m for m in MUTANTS if not a.only or m[0] in a.only.split(",")]
    tmp = Path(tempfile.mkdtemp(prefix="nawah-mutants-"))
    wt = tmp / "wt"
    scratch = tmp / "scratch-evidence"
    scratch.mkdir()
    subprocess.run(["git", "worktree", "add", "-q", "--detach", str(wt), "HEAD"], cwd=REPO, check=True)
    report = {"threshold": THRESHOLD, "target": a.target, "mutants": [], "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        env = dict(os.environ, NAWAH_ROOT=str(wt), NAWAH_SCRATCH_EVIDENCE=str(scratch), NAWAH_QEMU_TIMEOUT_S="90")
        env.setdefault("RUSTUP_TOOLCHAIN", os.environ.get("RUSTUP_TOOLCHAIN", ""))
        if not env["RUSTUP_TOOLCHAIN"]:
            del env["RUSTUP_TOOLCHAIN"]
        for m in mutants:
            mid, rel, old, new, killers, note = m
            t0 = time.time()
            entry = {"id": mid, "file": rel, "note": note, "killers": killers}
            reset(wt)
            try:
                apply(wt, m)
            except RuntimeError as ex:
                entry.update(status="invalid", reason=str(ex)); report["mutants"].append(entry); print(f"{mid}: INVALID ({ex})"); continue
            if a.check:
                r = sh(["cargo", "check", "--offline", "--manifest-path", "kernel/Cargo.toml", "--target", "x86_64-unknown-linux-gnu",
                        "--features", "ktest", "--target-dir", str(tmp / "check-target")], wt,
                       dict(env, NAWAH_BUILD_ID="mutcheck"))
                ok = r.returncode == 0
                entry.update(status="compiles" if ok else "invalid", seconds=round(time.time() - t0, 1))
                if not ok:
                    entry["reason"] = r.stdout[-1500:]
                report["mutants"].append(entry)
                print(f"{mid}: {'compiles' if ok else 'DOES NOT COMPILE'} ({note})")
                continue
            benv = dict(env, NAWAH_BUILD_ID=f"mut{mid.lower()}", NAWAH_OUT=str(wt / "build" / a.target),
                        NAWAH_APPS_DIR=str(wt / "build" / a.target / "apps"))
            (wt / "build" / a.target / "apps").mkdir(parents=True, exist_ok=True)
            need_release = "TST-M1-BOOT" in killers
            build_ok = True
            steps = [(APPS_STEP, APPS_OUT, "apps/hello.elf"), (KTEST_STEP, KTEST_OUT, "NAWAH-KTEST.EFI")]
            if need_release:
                steps.append((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"))
            for step, out, name in steps:
                r = sh(step, wt, benv, timeout=1800)
                if r.returncode != 0:
                    build_ok = False
                    entry["reason"] = r.stdout[-2000:]
                    break
                shutil.copy(wt / out, wt / "build" / a.target / name)
            if not build_ok:
                entry.update(status="invalid", seconds=round(time.time() - t0, 1)); report["mutants"].append(entry)
                print(f"{mid}: INVALID (does not build) ({note})"); continue
            (wt / "build" / a.target / "build-id.txt").write_text(benv["NAWAH_BUILD_ID"] + "\n")
            killed_by, results = run_killers(wt, env, a.target, killers)
            declared_miss = not killed_by
            if not killed_by:
                # Be fair before declaring a survivor: build the remaining artifacts and run
                # everything the suites have.
                rest = [c for c in all_cases(a.target) if c not in killers]
                for step, out, name in ((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"), (NEG_STEP, NEG_OUT, "NAWAH-NEG.EFI")):
                    if (wt / "build" / a.target / name).exists() and name == "NAWAH.EFI" and need_release:
                        continue
                    r = sh(step, wt, benv, timeout=1800)
                    if r.returncode == 0:
                        shutil.copy(wt / out, wt / "build" / a.target / name)
                more_killed, more = run_killers(wt, env, a.target, rest)
                results.update(more); killed_by = more_killed
            if declared_miss:
                # Keep the scratch evidence (serial logs) of anything that escaped its declared
                # killers, so the report can be audited.
                keep = REPO / "build" / "mutants-scratch" / mid
                if keep.exists():
                    shutil.rmtree(keep)
                shutil.copytree(scratch, keep)
                entry["declared_killers_missed"] = True
            for d in scratch.iterdir():
                shutil.rmtree(d, ignore_errors=True)
            entry.update(status="killed" if killed_by else "survived", killed_by=killed_by, results=results,
                         seconds=round(time.time() - t0, 1))
            report["mutants"].append(entry)
            print(f"{mid}: {'killed by ' + ','.join(killed_by) if killed_by else 'SURVIVED'} [{entry['seconds']}s] ({note})")
    finally:
        reset(wt)
        subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=REPO)
        shutil.rmtree(tmp, ignore_errors=True)
    valid = [m for m in report["mutants"] if m["status"] in ("killed", "survived")]
    killed = [m for m in valid if m["status"] == "killed"]
    ratio = len(killed) / len(valid) if valid else 0.0
    report.update(valid=len(valid), killed=len(killed), survived=[m["id"] for m in valid if m["status"] == "survived"],
                  declared_killers_missed=[m["id"] for m in report["mutants"] if m.get("declared_killers_missed")],
                  invalid=[m["id"] for m in report["mutants"] if m["status"] == "invalid"], ratio=round(ratio, 4),
                  finished=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    rp = REPO / a.report
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=1) + "\n")
    if a.check:
        bad = [m["id"] for m in report["mutants"] if m["status"] == "invalid"]
        print(f"\n{'OK' if not bad else 'FAIL'}: {len(report['mutants']) - len(bad)}/{len(report['mutants'])} mutants apply and type-check" + (f"; invalid: {bad}" if bad else ""))
        return 0 if not bad else 1
    verdict = ratio >= THRESHOLD and valid
    print(f"\n{'OK' if verdict else 'FAIL'}: {len(killed)}/{len(valid)} valid mutants killed ({ratio:.1%}, threshold {THRESHOLD:.0%}); survived={report['survived']}; invalid={report['invalid']}; declared_killers_missed={report['declared_killers_missed']}; report={a.report}")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
