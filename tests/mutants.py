#!/usr/bin/env python3
"""TST-M2-MUTANTS (REQ-M2-014), TST-M3-MUTANTS (REQ-M3-010, WP-22) and TST-M4-MUTANTS
(REQ-M4-010, WP-31): seeded-defect mutation testing of the kernel and the system services
against the guest suites — M01..M29 cover arch/, mm/ and sync (M1/M2 suites); M30..M49 cover the
M3 modules (scheduler, objects, syscalls, ELF loader, MMIO window, TLB shootdown, SMP placement,
virtio-blk, FAT32, VFS) and are killed by M3 cases, including the host checks a case runs on the
disk image; M50 onwards cover the M4 modules (process/wait syscalls, tokens, device objects and
polling, system_info, dir_list, and the user-space services svcmgr, authd, configd, netd, sh)
and are killed by M4 cases, console sessions included; M82 onwards cover the M5 modules (displayd,
inputd, sessiond, libui, libnawah-text; TST-M5-MUTANTS, WP-38) and are killed by M5 cases, the
host suites included (libui's unit tests, the text conformance suites). `--stage` selects one
group. A mutant in SECURITY undoes a security fix: the run fails if it survives, whatever the
ratio.

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
PASS = kill ratio >= 0.95 over valid mutants and no surviving SECURITY mutant. `--check` only
applies/reverts the patches and type-checks them on the host target (what this sandbox can do
without the UEFI toolchain).

Watchdog and exit codes (see docs/mutation-policy.md): every mutant has a per-mutant ceiling
(--watchdog-seconds, 600 s as the preparatory safety net; the final value is derived from the
measurements as max(300 s, 2 x p95)). A declared killer that exceeds it is `timeout-killed`: the
hang is the mutated kernel's, so it counts as a kill, not a survivor. A timeout during the build
or during the fairness sweep is `infra-error` and is never a kill. Exit codes: 0 = the gate
passes; 1 = a gate failure (a surviving mutant, a surviving SECURITY mutant, or ratio below the
threshold); 2 = budget/infrastructure (build timeout, fairness timeout, unreadable report, worktree
or driver failure) — not a gate verdict. Reports are mutants-mN-report.json per gate, written
partially at every exit, with mutants-mN-progress.jsonl appended after each mutant; a later run
resumes the terminal entries of the previous partial report.
"""
import argparse, json, os, signal, subprocess, sys, tempfile, time, shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
THRESHOLD = 0.95
# Preparatory per-mutant safety net (the run of 2026-10-29 hit the 3 h step cap). The final
# ceiling is derived from that run's measurements as max(300 s, 2 x p95) and set with
# --watchdog-seconds; 600 s here is only the safety net, never the gate's verdict.
WATCHDOG_S = 600
EXIT_OK, EXIT_GATE, EXIT_INFRA = 0, 1, 2


class MutantTimeout(Exception):
    """A test command of the mutant exceeded the per-mutant watchdog (a hang in the mutant)."""

    def __init__(self, tid):
        self.tid = tid
        super().__init__(f"watchdog fired during {tid}")


class InfraError(Exception):
    """The run cannot attribute the overrun to the mutated kernel: budget, build or fairness."""


class Budget:
    def __init__(self, seconds):
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())


def run_bounded(cmd, cwd, env, budget, phase, tid=None, hard=1800):
    """`sh` bounded by both the step's own hard limit and the mutant's watchdog. A timeout in
    `phase` 'test' is a hang of the mutated kernel (MutantTimeout); in 'build' or between
    steps it is an infrastructure overrun (InfraError): never a verdict on the mutant."""
    left = budget.remaining()
    if left <= 0:
        raise InfraError(f"watchdog {budget.seconds}s exhausted before {phase} {tid or ''}".strip())
    try:
        return sh(cmd, cwd, env, timeout=min(float(hard), left))
    except subprocess.TimeoutExpired:
        if phase == "test":
            raise MutantTimeout(tid)
        raise InfraError(f"watchdog {budget.seconds}s fired during {phase} {tid or ''}".strip())


def report_name(stage):
    """mutants-mN-report.json for every gate (M2 included; the old bare mutants-report.json is
    only kept when no gate is selected)."""
    return f"build/mutants-{stage.lower()}-report.json" if stage else "build/mutants-report.json"


def progress_name(report):
    s = str(report)
    return s[:-len("-report.json")] + "-progress.jsonl" if s.endswith("-report.json") else s + ".progress.jsonl"


def write_report(path, report):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def append_progress(path, entry):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


DONE = ("killed", "survived", "timeout-killed", "invalid")


def previous_entries(progress, report):
    """Resume: the terminal entries of an earlier partial run, by id (progress lines first,
    then the partial report). A partially written line is ignored."""
    out = {}
    p = Path(progress)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and e.get("id") and e.get("status") in DONE:
                out[e["id"]] = e
        return out
    p = Path(report)
    if p.exists():
        try:
            rep = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return out
        for e in rep.get("mutants", []):
            if e.get("id") and e.get("status") in DONE:
                out[e["id"]] = e
    return out


def finalize(report, partial, exit_code=None):
    ms = report["mutants"]
    valid = [m for m in ms if m["status"] in ("killed", "timeout-killed", "survived")]
    killed = [m for m in valid if m["status"] in ("killed", "timeout-killed")]
    survived = [m["id"] for m in valid if m["status"] == "survived"]
    report.update(
        valid=len(valid), killed=len(killed), survived=survived,
        timeout_killed=[m["id"] for m in ms if m["status"] == "timeout-killed"],
        invalid=[m["id"] for m in ms if m["status"] == "invalid"],
        infra_error=[m["id"] for m in ms if m["status"] == "infra-error"],
        declared_killers_missed=[m["id"] for m in ms if m.get("declared_killers_missed")],
        ratio=round(len(killed) / len(valid), 4) if valid else 0.0,
        surviving_security=[m for m in survived if security_of(m)],
        partial=partial, exit_code=exit_code,
        finished=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    return report


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
    # PMM-COUNTS caught this while the boot left the first MiB's frames unallocated; since the
    # scheduler reserves its tables at init (WP-31) the boot itself consumes those frames under
    # the mutant and the test's 1024 frames all come from above 1 MiB (mutants run
    # 39144910448: killed by TST-M1-BOOT and PMM-EXHAUST instead). The declaration follows the
    # cases that see the defect now.
    ("M07", "kernel/src/mm/pmm.rs",
     "const LOW_RESERVED: u64 = 1 << 20; // 1 MiB", "const LOW_RESERVED: u64 = 0; // 1 MiB",
     ["TST-M1-BOOT", "TST-M2-PMM-EXHAUST"], "first MiB handed out"),
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
     "    // Software-enable first: while disabled, LVT mask bits are forced to 1 (§11.4.7.2).\n    write(REG_SVR, SVR_ENABLE | u32::from(spurious_vector));",
     "    // Software-enable first: while disabled, LVT mask bits are forced to 1 (§11.4.7.2).\n    write(REG_SVR, SVR_ENABLE | 0xFE);",
     ["TST-M2-SPURIOUS"], "wrong spurious vector programmed"),
    ("M19", "kernel/src/arch/x86_64/irq.rs",
     "    apic::eoi();\n    DEPTH[cpu].fetch_sub(1, Ordering::Relaxed);", "    apic::eoi();",
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
    # ---- M3 (WP-22): scheduler, objects, syscalls, loader, memory, SMP, storage, files ----
    ("M30", "kernel/src/sched/mod.rs",
     "        t.slice = t.slice.saturating_sub(1);\n        if t.slice == 0 {",
     "        if t.slice == 0 {",
     ["TST-M3-PREEMPT", "TST-M3-LOCK-CONTENTION"], "time slice never expires (no preemption)"),
    ("M31", "kernel/src/sched/mod.rs",
     "                if prio < bp || (prio == bp && t.last_pick < bt.last_pick) {",
     "                if t.last_pick < bt.last_pick {",
     ["TST-M3-PRIORITY-ORDER"], "priorities ignored by pick_next (round-robin only)"),
    ("M32", "kernel/src/sched/mod.rs",
     "                p.threads -= 1;\n                if p.threads == 0 {",
     "                if p.threads == 0 {",
     ["TST-M1-BOOT", "TST-M3-USER-SYSCALL"], "a process never finishes (thread count not decremented)"),
    ("M33", "kernel/src/sched/mod.rs",
     "                _ => t.wake_tokens = t.wake_tokens.saturating_add(1),",
     "                _ => {}",
     ["TST-M3-BLOCK-WAKE"], "a wake-up before the block is lost (no token)"),
    ("M34", "kernel/src/syscall/mod.rs",
     "        let ep = endpoint_of(t.get(h, Rights::WRITE).map_err(handle_err)?)?;",
     "        let ep = endpoint_of(t.get(h, Rights(0)).map_err(handle_err)?)?;",
     ["TST-M3-RIGHTS-DENIED"], "channel_write ignores the WRITE right"),
    ("M35", "kernel/src/object/handle.rs",
     "        s.generation = match s.generation.wrapping_add(1) {\n            0 => 1,\n            g => g,\n        };\n        self.live -= 1;",
     "        self.live -= 1;",
     ["TST-M3-CLOSED-HANDLE"], "a closed handle's slot keeps its generation (stale handle accepted)"),
    ("M36", "kernel/src/syscall/mod.rs",
     "    if len > MSG_MAX_BYTES as u64 || nh > MSG_MAX_HANDLES as u64 {",
     "    if nh > MSG_MAX_HANDLES as u64 {",
     ["TST-M3-IPC-OVERSIZE"], "oversize message accepted by channel_write"),
    # The USER-bit half of this check is equivalent today (no supervisor page lies in the user
    # range: the kernel image is below USER_BASE, everything else in the higher half — mutants
    # run 39116036466 showed it), so the mutant drops the WRITE half, which a syscall writing
    # into a read-only user page would expose as a kernel #PF.
    ("M37", "kernel/src/syscall/mod.rs",
     "            Some(f) if f & arch::paging::USER != 0 && (!write || f & arch::paging::WRITE != 0) => {}",
     "            Some(f) if f & arch::paging::USER != 0 => {}",
     ["TST-M3-PATH-INVALID"], "a syscall may write into a read-only user page (WRITE bit not checked)"),
    ("M38", "kernel/src/loader/elf.rs",
     "        if s.flags & 0x3 == 0x3 {\n            return Err(ElfError::WritableExecutable);\n        }",
     "",
     ["TST-M3-ELF-WX"], "W^X not enforced on PT_LOAD segments"),
    ("M39", "kernel/src/loader/elf.rs",
     "            if lo < ohi && olo < hi {\n                return Err(ElfError::SegmentOverlap);\n            }",
     "",
     ["TST-M3-ELF-MALFORMED"], "overlapping segments accepted"),
    ("M40", "kernel/src/mm/vmm.rs",
     "    let virt = w.next;\n    let mut page = start;",
     "    let virt = start;\n    let mut page = start;",
     ["TST-M1-BOOT", "TST-M3-BLK-USER-CR3"], "MMIO mapped at its physical address again (CI run 39110182649 regression)"),
    ("M41", "kernel/src/mm/vmm.rs",
     "    paging::invlpg(virt);\n    crate::arch::tlb::shootdown(virt, PAGE_4K);\n    Ok(phys)",
     "    paging::invlpg(virt);\n    Ok(phys)",
     ["TST-M3-TLB-SHOOTDOWN"], "unmap_page does not tell the other CPUs"),
    ("M42", "kernel/src/arch/x86_64/tlb.rs",
     "            flush_range(addr, len);\n            SERVED.fetch_add(1, Ordering::Relaxed);",
     "            SERVED.fetch_add(1, Ordering::Relaxed);",
     ["TST-M3-TLB-SHOOTDOWN"], "a served shootdown request flushes nothing"),
    ("M43", "kernel/src/sched/mod.rs",
     "        owns_stack: true,\n        cpu: cpu as u8,",
     "        owns_stack: true,\n        cpu: me() as u8,",
     ["TST-M3-SMP-ONLINE"], "spawn_on places the thread on the caller's CPU"),
    ("M44", "kernel/src/arch/x86_64/mod.rs",
     "    unsafe { asm!(\"mov {}, gs:[16]\", out(reg) id, options(nostack, readonly, preserves_flags)) };\n    id as u32",
     "    unsafe { asm!(\"mov {}, gs:[16]\", out(reg) id, options(nostack, readonly, preserves_flags)) };\n    (id & 0) as u32",
     ["TST-M3-SMP-ONLINE", "TST-M3-LOCK-CONTENTION"], "every CPU believes it is CPU 0"),
    ("M45", "kernel/src/drivers/virtio_blk.rs",
     "            .is_none_or(|e| e > self.info.capacity_sectors)",
     "            .is_none_or(|e| e > self.info.capacity_sectors + 8)",
     ["TST-M3-BLK-READ"], "reads past the capacity accepted"),
    ("M46", "kernel/src/fs/fat32.rs",
     "        for k in 0..self.fats {\n            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;",
     "        for k in 0..1 {\n            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;",
     ["TST-M3-FILE-ROUNDTRIP", "TST-M3-FD-LEAK", "TST-M3-FAT32-PERSIST"],
     "only the first FAT is updated (fsck on an image with files left: FATs differ)"),
    ("M47", "kernel/src/fs/fat32.rs",
     "        let freed = if e.first >= 2 {\n            self.free_chain(e.first)?\n        } else {\n            0\n        };",
     "        let freed = 0;",
     ["TST-M3-FAT32-WRITE"], "unlink leaks the cluster chain"),
    ("M48", "kernel/src/fs/vfs.rs",
     "    if path.is_empty() || path.len() > PATH_MAX || path[0] != b'/' || !path.is_ascii() {",
     "    if path.is_empty() || path.len() > PATH_MAX || !path.is_ascii() {",
     ["TST-M3-PATH-INVALID"], "relative paths accepted"),
    # Unknown open flags are refused twice with the same ABI answer (sys_open and vfs::open
    # both map to ERR_INVALID), so removing either check alone is an equivalent mutant (mutants
    # runs 39120514522 and 39122407455); the defect seeded here is in the rights an open
    # handle receives instead.
    ("M49", "kernel/src/syscall/mod.rs",
     "    if flags & vfs::O_WRITE != 0 {\n        rights = Rights(rights.0 | Rights::WRITE.0);\n    }",
     "    rights = Rights(rights.0 | Rights::WRITE.0);",
     ["TST-M3-FILE-ROUNDTRIP"], "every open handle gets the WRITE right (read-only open can write)"),
    # ---- M4 (WP-31): services and their authority; killers are M4 cases ----
    ("M50", "kernel/src/syscall/mod.rs",
     "            Some(d) if sched::ticks() >= d => break Err(ERR_TIMED_OUT),",
     "            Some(d) if sched::ticks() >= d.saturating_mul(1000) => break Err(ERR_TIMED_OUT),",
     ["TST-M4-WAIT-TIMEOUT"], "object_wait_many's timeout never expires"),
    ("M51", "kernel/src/object/token.rs",
     "        self.revoked.store(true, Ordering::Release);",
     "        self.revoked.store(false, Ordering::Release);",
     ["TST-M4-TOKEN-OBJECTS", "TST-M4-SESSION-LOCK"], "token_revoke is a no-op"),
    ("M52", "kernel/src/object/token.rs",
     "        self.expires != 0 && now >= self.expires",
     "        self.expires != 0 && now >= self.expires.saturating_add(1_000_000)",
     ["TST-M4-TOKEN-OBJECTS"], "a token expires 1000 s late"),
    ("M53", "kernel/src/syscall/mod.rs",
     "        Object::Authority(_) => {}\n        _ => return Err(ERR_ACCESS),\n    }\n    let token = Arc::new(",
     "        _ => {}\n    }\n    let token = Arc::new(",
     ["TST-M4-WAIT-TIMEOUT"], "any handle mints tokens (the authority check removed; the waiter app probes it)"),
    ("M54", "kernel/src/object/mod.rs",
     "            Object::Nic(_) => 7,", "            Object::Nic(_) => 8,",
     ["TST-M4-DHCP", "TST-M4-NET-LINK"], "handle_type reports the interface as a keyboard (the manager misroutes it)"),
    ("M55", "kernel/src/drivers/virtio_net.rs",
     "            self.stats.tx_busy += 1;\n            return Err(NetError::Busy);",
     "            self.stats.tx_busy += 1;\n            return Ok(());",
     ["TST-M4-NET-LIMITS"], "a full transmit ring drops the frame silently instead of Busy"),
    ("M56", "kernel/src/net.rs",
     "    while polled < 8 {", "    while polled < 0 {",
     ["TST-M4-KBD-SCANCODES"], "the keyboard is never polled"),
    ("M57", "kernel/src/diag.rs",
     "    for _ in 0..16 {", "    for _ in 0..0 {",
     ["TST-M4-SHELL-SVC", "TST-M4-SHELL-LOGIN"], "the console is never polled"),
    ("M58", "kernel/src/syscall/mod.rs",
     "    rec[24..32].copy_from_slice(&pmm.managed_frames.to_le_bytes());",
     "    rec[24..32].copy_from_slice(&pmm.free_frames.to_le_bytes());",
     ["TST-M4-SHELL-SVC"], "system_info reports the free frames as the total"),
    ("M59", "kernel/src/fs/vfs.rs",
     "            if e.is_dir() {\n                put(b\"D \");", "            if false {\n                put(b\"D \");",
     ["TST-M4-SHELL-SVC"], "dir_list lists directories as files"),
    ("M60", "kernel/src/syscall/mod.rs",
     "                | Object::Serial(_)\n                | Object::Mouse(_) => {}",
     "                | Object::Serial(_)\n                | Object::Mouse(_)\n                | Object::Vmo(_) => {}",
     ["TST-M4-WAIT-TIMEOUT"], "object_wait_many accepts a VMO"),
    ("M61", "kernel/src/services.rs",
     "    if crate::diag::present() {\n        initial.push(Entry {",
     "    if !crate::diag::present() {\n        initial.push(Entry {",
     ["TST-M4-SHELL-SVC", "TST-M1-BOOT"], "the console is handed to the manager only when absent"),
    ("M62", "user/apps/svcmgr/src/main.rs",
     "            b\"auth\" => [\n                (self.authority, ALL_RIGHTS),",
     "            b\"auth\" => [\n                (None, ALL_RIGHTS),",
     ["TST-M4-LOGIN"], "the authority is never handed to auth"),
    ("M63", "user/apps/svcmgr/src/main.rs",
     "                } else if self.services[i].deps & !ready == 0 {\n                    self.start(i, now);",
     "                } else {\n                    self.start(i, now);",
     ["TST-M4-SVC-ORDER"], "dependents start before their dependencies are ready"),
    # Re-anchored on the watchdog's deeper nesting and the forced kill of a service hung before
    # READY (WP-40, services.md v1.8): the whole timeout arm is dropped but the disarm.
    ("M64", "user/apps/svcmgr/src/main.rs",
     "                        State::Starting => {\n                            self.services[i].state = State::Failed;\n                            self.services[i].deadline = None;\n                            self.close_chan(i);\n                            // A cooperative service exits on the close; one hung before READY\n                            // never reads its channel, so it is forced after the grace (v1.8).\n                            if self.services[i].process.is_some() {\n                                self.services[i].kill_at = Some(now.saturating_add(STOP_GRACE));\n                            }\n                        }",
     "                        State::Starting => {\n                            self.services[i].deadline = None;\n                        }",
     ["TST-M4-SVC-TIMEOUT"], "a readiness timeout is ignored"),
    ("M65", "user/apps/svcmgr/src/main.rs",
     "        if s.restart_on_failure && s.restarts < s.max_restarts {",
     "        if s.restart_on_failure {",
     ["TST-M4-SVC-RESTART"], "the restart limit is ignored (never given up)"),
    ("M66", "user/apps/svcmgr/src/main.rs",
     "            s.deadline = Some(now.saturating_add(s.backoff << shift));",
     "            s.deadline = Some(now.saturating_add(s.backoff));",
     ["TST-M4-SVC-RESTART"], "the backoff does not double"),
    ("M67", "user/apps/svcmgr/src/main.rs",
     "            Some(j) if self.services[i].deps & (1 << j) == 0 => out.put(b\"ERR ACCESS\"),",
     "            Some(j) if self.services[i].deps & (1 << j) == 0 && false => out.put(b\"ERR ACCESS\"),",
     ["TST-M4-SHELL-SVC"], "a service connects to any service, declared or not"),
    ("M68", "user/apps/authd/src/main.rs",
     "        let ok = ct_eq(&dk, &u.hash);", "        let ok = ct_eq(&dk, &u.hash) || !dk.is_empty();",
     ["TST-M4-LOGIN", "TST-M4-SHELL-LOGIN"], "any password is accepted"),
    ("M69", "user/apps/authd/src/main.rs",
     "        if self.fails < MAX_FAILS {", "        if self.fails < MAX_FAILS + 1000 {",
     ["TST-M4-LOGIN"], "the attempt limit never delays"),
    ("M70", "user/apps/authd/src/main.rs",
     "    fn close_session(&mut self, slot: usize) {\n        let s = &mut self.sessions[slot];\n        libnawah::token_revoke(s.token);",
     "    fn close_session(&mut self, slot: usize) {\n        let s = &mut self.sessions[slot];",
     ["TST-M4-SESSION-LOCK"], "LOGOUT does not revoke the token"),
    ("M71", "user/apps/configd/src/main.rs",
     "        if current != expected {\n            out.put(b\"ERR VERSION \");",
     "        if false {\n            out.put(b\"ERR VERSION \");",
     ["TST-M4-CONFIG-CAS"], "the compare-and-set ignores the expected version"),
    ("M72", "user/apps/configd/src/main.rs",
     "                    if let Some(cached) = st.clients[ci].cache.iter().find(|e| e.rid == rid) {",
     "                    if let Some(cached) = st.clients[ci].cache.iter().find(|e| e.rid == rid && false) {",
     ["TST-M4-CONFIG-RETRY"], "a repeated request_id is applied again"),
    ("M73", "user/apps/configd/src/main.rs",
     "            DEVICE => admin || token.perms & perm::CONFIG_WRITE != 0,",
     "            DEVICE => true,",
     ["TST-M4-AUTHZ-DENIED"], "any token may write the device store"),
    ("M74", "user/apps/configd/src/main.rs",
     "                    (Some(POLICY), &b\"policy\"[..]),\n                    (user_store, b\"user\"),",
     "                    (user_store, &b\"user\"[..]),\n                    (Some(POLICY), b\"policy\"),",
     ["TST-M4-POLICY-PRECEDENCE"], "the user value takes precedence over the policy"),
    ("M75", "user/apps/configd/src/main.rs",
     "            if h != 0 && libnawah::channel_write(h, &msg[..len], &[]) != 0 {",
     "            if h != 0 && libnawah::channel_write(h, &msg[..len.min(7)], &[]) != 0 {",
     ["TST-M4-CONFIG-NOTIFY"], "subscribers get a truncated CHANGED notification"),
    ("M76", "user/apps/netd/src/main.rs",
     "        let c = checksum(&[&self.tx_frame[o..o + 20]]);", "        let c: u16 = 0;",
     ["TST-M4-DHCP"], "IPv4 packets go out without a header checksum"),
    ("M77", "user/apps/netd/src/main.rs",
     "        self.allow_internet || self.on_link(ip) || ip == self.gateway",
     "        true || self.on_link(ip) || ip == self.gateway",
     ["TST-M4-NET-NO-INTERNET"], "the no-internet policy is not applied"),
    ("M78", "user/apps/netd/src/main.rs",
     "            if now < due || c.snd_una == c.snd_nxt {", "            if true {",
     ["TST-M4-TCP-RETRANSMIT"], "the retransmission timer never fires"),
    ("M79", "user/apps/netd/src/main.rs",
     "                if !c.retransmitted {\n                    let r = now.saturating_sub(c.sent_at);",
     "                if true {\n                    let r = now.saturating_sub(c.sent_at);",
     ["TST-M4-TCP-RETRANSMIT"], "an RTT sample is taken from a retransmitted segment (Karn's rule dropped)"),
    ("M80", "user/apps/sh/src/main.rs",
     "                            self.ask(chan, &req[..7 + n], &[t], out);",
     "                            self.ask(chan, &req[..7 + n], &[], out);",
     ["TST-M4-SHELL-LOGIN"], "the shell sends a protected request without the session token"),
    ("M81", "user/apps/sh/src/main.rs",
     "            out[n] = b'@';", "            out[n] = b'#';",
     ["TST-M4-SHELL-LOGIN"], "the prompt does not show the session's user"),
    # ---- M5 gate (WP-38): display, input, session, ui, text. The 2026-10-19 pre-gate review's
    # findings (WP-43) each get the mutant that removes the fix, so the test that proved the
    # fix proves it can see the fix gone. `security` names a mutant that must not survive
    # whatever the ratio (security_of).
    ("M82", "user/apps/displayd/src/main.rs",
     "                if !self.clients[ci].narrator {\n                    out.put(b\"ERR ACCESS\");\n                } else if self.narrator.is_some_and(|n| n != ci) {",
     "                if self.narrator.is_some_and(|n| n != ci) {",
     ["TST-M5-NARRATOR-AUTHORITY"], "any client may become the narrator (WP-43 M2 undone)"),
    ("M83", "user/apps/displayd/src/main.rs",
     "                if self.surfaces.iter().filter(|s| used(s)).count() >= CLIENT_SURFACES {",
     "                if self.surfaces.iter().filter(|s| used(s)).count() > CLIENT_SURFACES {",
     ["TST-M5-CLIENT-LIMITS"], "a client gets one surface more than its share (WP-43 S-7, boundary)"),
    ("M84", "user/apps/displayd/src/main.rs",
     "                if mine >= CLIENT_WINDOWS {\n                    out.put(b\"ERR LIMIT\");\n                    return false;\n                }",
     "",
     ["TST-M5-CLIENT-LIMITS"], "no per-client window limit (WP-43 S-7 undone)"),
    ("M85", "user/apps/displayd/src/main.rs",
     "const SESSION_RESERVE: usize = 2;", "const SESSION_RESERVE: usize = 0;",
     ["TST-M5-CLIENT-LIMITS"], "no surfaces or windows kept for the session (WP-43 S-7)"),
    ("M86", "user/apps/displayd/src/main.rs",
     "        if !self.visible(wi) {\n            return false;\n        }\n        let area = w.client().intersect(self.screen);",
     "        let area = w.client().intersect(self.screen);",
     ["TST-M5-LIST-HASH-HELD"], "LIST hashes a held or minimised window's place (WP-43 M3 undone)"),
    ("M87", "user/apps/displayd/src/main.rs",
     "        if !self.locked {\n            self.composed += 1;\n        }",
     "        self.composed += 1;",
     ["TST-M5-LIST-HASH-HELD"], "STATUS counts the held screen's redraws, one per key typed (WP-43 M3 undone)"),
    ("M88", "user/apps/sessiond/src/main.rs",
     "                if self.dialog.element(i).role != Role::Password {\n                    self.announce(b\"change\", Some(i));\n                }",
     "                self.announce(b\"change\", Some(i));",
     ["TST-M5-AUTH-INPUT-ISOLATED"], "the password field announces every keystroke (WP-43 M2 undone)"),
    ("M89", "user/apps/sessiond/src/main.rs",
     "        self.take_keyboard();\n        if self.owner != Owner::Session {\n            self.elevate_end(b\"ERR UNAVAILABLE\", now);\n            return;\n        }\n        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);\n        self.show(Screen::Elevate, None);",
     "        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);\n        self.show(Screen::Elevate, None);\n        self.take_keyboard();\n        if self.owner != Owner::Session {\n            self.elevate_end(b\"ERR UNAVAILABLE\", now);\n            return;\n        }",
     ["TST-M5-ELEVATE"], "the elevation prompt is shown before the keyboard is taken (WP-41 S1 undone, order swapped)"),
    ("M90", "user/apps/inputd/src/main.rs",
     "                if name == b\"display\" && self.clients[ci].ident() != b\"display\" {\n                    out.put(b\"ERR ACCESS\");\n                    return;\n                }",
     "",
     ["TST-M5-INPUT-NAME-RESERVED"], "any client may register the name `display` (WP-43 S-5 undone)"),
    ("M91", "user/libui/src/lib.rs",
     "                        if e.role == Role::Password {\n                            s[..e.text_len].fill(BULLET);\n                        }",
     "",
     ["TST-M5-UI-UNIT"], "a password field draws its characters instead of bullets"),

    # ---- M5 gate (WP-38), batch 2 (M92-M121): display, input, session, ui, text.
    ("M92", "user/apps/displayd/src/main.rs",
     "        !w.minimized && (!self.locked || self.clients[w.owner].session)",
     "        w.minimized && (!self.locked || self.clients[w.owner].session)",
     ["TST-M5-WINDOW-STATES"], "[condition-flip] a minimised window is shown instead of a normal one"),
    ("M93", "user/apps/displayd/src/main.rs",
     "        w.used && (!self.locked || self.clients[w.owner].session)",
     "        w.used",
     ["TST-M5-LOCK-SURVIVES"], "[delete-check] the lock no longer hides other clients from Alt+Tab"),
    ("M94", "user/apps/displayd/src/main.rs",
     "        (0..k).all(|j| {",
     "        (0..k.saturating_sub(1)).all(|j| {",
     ["TST-M5-LIST-HASH-HELD"], "[boundary-shift] the overlap check skips the window just above"),
    ("M95", "user/apps/displayd/src/main.rs",
     "        self.windows[wi].used = false;\n",
     "",
     ["TST-M5-WINDOW-STATES"], "[assignment-delete] a destroyed window stays marked used"),
    ("M96", "user/apps/displayd/src/main.rs",
     "const CLIENT_WINDOWS: usize = 4;",
     "const CLIENT_WINDOWS: usize = 5;",
     ["TST-M5-CLIENT-LIMITS"], "[constant-change] one window more than the client limit"),
    ("M97", "user/apps/displayd/src/main.rs",
     "                        self.locked = true;\n                        let mut told = [false; MAX_CLIENTS];\n                        for wi in 0..MAX_WINDOWS {\n                            let owner = self.windows[wi].owner;\n                            if self.windows[wi].used && !self.clients[owner].session {\n                                told[owner] = true;\n                                self.destroy_window(wi, now);\n                            }\n                        }",
     "                        let mut told = [false; MAX_CLIENTS];\n                        for wi in 0..MAX_WINDOWS {\n                            let owner = self.windows[wi].owner;\n                            if self.windows[wi].used && !self.clients[owner].session {\n                                told[owner] = true;\n                                self.destroy_window(wi, now);\n                            }\n                        }\n                        self.locked = true;",
     ["TST-M5-LOGIN-SCREEN"], "[order-swap] windows go before the screen is held (LOGOUT order)"),
    ("M98", "user/apps/sessiond/src/main.rs",
     "        self.state = State::Locked;\n        if self.elevation.is_some() {\n            self.elevate_end(b\"ERR CANCELLED\", now);\n            self.want_display = false;\n        }\n        self.changes += 1;\n        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);",
     "        if self.elevation.is_some() {\n            self.elevate_end(b\"ERR CANCELLED\", now);\n            self.want_display = false;\n        }\n        self.changes += 1;\n        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);\n        self.state = State::Locked;",
     ["TST-M5-LOCK-SURVIVES"], "[order-swap] LOCKED before the state changes"),
    ("M99", "user/apps/sessiond/src/main.rs",
     "        // The secret leaves the element at once; it lives in `pw` and the request only.\n        self.dialog.clear_value(self.ids.password);",
     "        // The secret leaves the element at once; it lives in `pw` and the request only.\n        // mutation: deleted clear_value()",
     ["TST-M5-AUTH-INPUT-ISOLATED"], "[order-swap] the password stays in the field after LOGIN"),
    ("M100", "user/apps/sessiond/src/main.rs",
     "        let same = self.elevation.is_some_and(|e| e.n == n);",
     "        let same = true;",
     ["TST-M5-ELEVATE"], "[delete-check] any elevation answer is taken for the current one"),
    ("M101", "user/apps/sessiond/src/main.rs",
     "        if self.elevation.is_some() {",
     "        if self.elevation.is_none() {",
     ["TST-M5-ELEVATE"], "[condition-flip] a prompt is not cancelled by the secure attention sequence"),
    ("M102", "user/apps/sessiond/src/main.rs",
     "        self.elevate_seq += 1;\n",
     "",
     ["TST-M5-ELEVATE"], "[assignment-delete] elevations share one number (stale answers match)"),
    ("M103", "user/apps/sessiond/src/main.rs",
     "const RELEASE_WAIT: u64 = 1000;",
     "const RELEASE_WAIT: u64 = 0;",
     ["TST-M5-FOCUS-AFTER-RESTART"], "[constant-change] no wait before releasing the screen"),
    ("M104", "user/apps/sessiond/src/main.rs",
     "                    if now >= deadline {",
     "                    if now >= deadline.saturating_add(REQUEST_DEADLINE) {",
     ["TST-M5-LOCK-AUTH-HANG"], "[boundary-shift] the request deadline is doubled"),
    ("M105", "user/apps/sessiond/src/main.rs",
     "            // The screen is released only to an unlocked desktop; a lock keeps it held.\n            if self.state == State::Unlocked {",
     "            // The screen is released only to an unlocked desktop; a lock keeps it held.\n            if self.state == State::Locked {",
     ["TST-M5-LOCK-SURVIVES"], "[condition-flip] a held screen is released while locked"),
    ("M106", "user/apps/inputd/src/main.rs",
     "        if &c.name[..c.name_len] == b\"session\" {\n            self.focus = None;\n        }\n",
     "",
     ["TST-M5-SESSION-LOSS"], "[delete-check] a lost session no longer clears the focus"),
    ("M107", "user/apps/inputd/src/main.rs",
     "                if let Some(s) = self.session_client() {",
     "if let Some(s) = self.clients.first().map(|_| 0) {",
     ["TST-M5-AUTH-INPUT-ISOLATED"], "[condition-flip] the SAK focuses client 0 instead of the session"),
    ("M108", "user/apps/inputd/src/main.rs",
     "                self.mods |= bit;",
     "                self.mods ^= bit;",
     ["TST-M5-ARABIC-UI"], "[order-swap] the arming step is an XOR instead of an OR"),
    ("M109", "user/apps/inputd/src/main.rs",
     "                if self.combo_armed && (bit == MOD_SHIFT || bit == MOD_ALT) {\n                    self.combo_armed = false;\n                    self.toggle_layout();\n                }",
     "                if self.combo_armed && (bit == MOD_SHIFT || bit == MOD_ALT) {\n                    self.toggle_layout();\n                }",
     ["TST-M5-ARABIC-UI"], "[assignment-delete] the Shift+Alt chord stays armed after a toggle"),
    ("M110", "user/apps/inputd/src/main.rs",
     "        let down = b & 0x80 == 0;",
     "        let down = b & 0x80 != 0;",
     ["TST-M5-INPUT-ROUTE"], "[boundary-shift] release scancodes are taken for presses"),
    ("M111", "user/libui/src/lib.rs",
     "            KEY_TAB => return self.step(mods & MOD_SHIFT != 0),",
     "            KEY_TAB => return self.step(mods & MOD_SHIFT == 0),",
     ["TST-M5-UI-UNIT"], "[condition-flip] Tab moves backwards (Shift+Tab forwards)"),
    ("M112", "user/libui/src/lib.rs",
     "        if i >= self.n || !self.elements[i].role.is_text() {\n            return 0;\n        }",
     "if i >= self.n { return 0; }",
     ["TST-M5-UI-UNIT"], "[delete-check] value() reads a password for any role"),
    ("M113", "user/libui/src/lib.rs",
     "            (r, KEY_BACKSPACE) if r.is_text() && e.cursor > 0 => {",
     "            (r, KEY_BACKSPACE) if r.is_text() && e.cursor > 1 => {",
     ["TST-M5-UI-UNIT"], "[boundary-shift] Backspace never deletes the last character"),
    ("M114", "user/libui/src/lib.rs",
     "                let forward = (code == KEY_RIGHT) != rtl;",
     "                let forward = (code == KEY_RIGHT) == rtl;",
     ["TST-M5-UI-UNIT"], "[order-swap] the arrow direction ignores the paragraph direction"),
    ("M115", "user/libnawah-text/src/bidi.rs",
     "                L => return 0,\n                R | AL => return 1,",
     "                L => return 1,\n                R | AL => return 0,",
     ["TST-M5-BIDI"], "[condition-flip] L and R/AL levels swap"),
    ("M116", "user/libnawah-text/src/bidi.rs",
     "        if c == cp {\n            return Some((pair, open));\n        }",
     "// mutation: removed bracket match",
     ["TST-M5-BIDI"], "[delete-check] brackets never match (N0 skipped)"),
    ("M117", "user/libnawah-text/src/shape.rs",
     "pub const JT_U: u8 = 0;",
     "pub const JT_U: u8 = 1;",
     ["TST-M5-SHAPING"], "[constant-change] U joins like R (joining type collision)"),
    ("M118", "user/libnawah-text/src/layout.rs",
     "                pen += adv;\n",
     "",
     ["TST-M5-SHAPING"], "[assignment-delete] glyph origins do not advance"),
    ("M119", "user/libnawah-text/src/font.rs",
     "                    if (u16_at(d, ends + mid * 2)? as u32) < cp {",
     "                    if (u16_at(d, ends + mid * 2)? as u32) <= cp {",
     ["TST-M5-GLYPHS"], "[boundary-shift] the cmap search skips the segment end"),
    ("M120", "user/libnawah-text/src/raster.rs",
     "const TOL: i64 = ONE / 64;",
     "const TOL: i64 = ONE * 64;",
     ["TST-M5-GLYPHS"], "[constant-change] the rasteriser tolerance is 64x too big"),
    ("M121", "user/libnawah-text/src/tables.rs",
     "pub static BRACKETS: [(u32, u32, bool); 128] = [\n    (0x28, 0x29, true),",
     "pub static BRACKETS: [(u32, u32, bool); 127] = [",
     ["TST-M5-BIDI"], "[delete-check] the first bracket pair is missing from the table"),
]

def stage_of(mid: str) -> str:
    """M01..M29 belong to the M2 gate (TST-M2-MUTANTS), M30..M49 to the M3 gate (TST-M3-MUTANTS),
    M50..M81 to the M4 gate (TST-M4-MUTANTS), M82.. to the M5 gate (TST-M5-MUTANTS, WP-38)."""
    n = int(mid[1:])
    return "M2" if n < 30 else ("M3" if n < 50 else ("M4" if n < 82 else "M5"))


# The M5 mutants that undo a security fix of the pre-gate review (WP-43) or of WP-41: the gate
# fails if any of them survives, whatever the kill ratio (the review's rule 1 of 2026-10-27).
SECURITY = {"M82", "M83", "M84", "M85", "M86", "M87", "M88", "M89", "M90", "M91", "M93", "M95", "M96", "M97", "M98", "M99", "M100", "M101", "M102", "M105", "M106", "M107", "M112"}


def security_of(mid: str) -> bool:
    return mid in SECURITY

# Applications first (WP-17): the kernel embeds them through NAWAH_APPS_DIR (kernel/build.rs).
def target_apps():
    """Every user app the pc-qemu build steps compile, in build order, read from
    platform/pc-qemu/target.json so this list cannot drift from the real build: a hand-kept
    copy lacked exiter, sessiond and spy after WP-40, so every mutant build would have failed
    (review 2026-10-19, M8)."""
    import re
    found = []

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            m = re.fullmatch(r"user/apps/([a-z0-9_]+)/Cargo.toml", o)
            if m:
                found.append(m.group(1))

    walk(json.loads((REPO / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))["build"])
    return list(dict.fromkeys(found))


APPS = target_apps()
def app_step(name):
    return (["cargo", "build", "--profile", "app", "--offline", "--manifest-path", f"user/apps/{name}/Cargo.toml",
             "--target", "x86_64-unknown-none", "--target-dir", "build/pc-qemu/cargo-user"],
            f"build/pc-qemu/cargo-user/x86_64-unknown-none/app/{name}", f"apps/{name}.elf")
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
    subprocess.run(["git", "checkout", "-q", "--", "kernel", "user"], cwd=wt, check=True)


def crate_of(rel: str):
    """The cargo package a mutated file belongs to (for `--check`): the kernel, or a user crate."""
    parts = Path(rel).parts
    if parts[0] == "kernel":
        return None
    if parts[:2] == ("user", "apps"):
        return parts[2]
    if parts[0] != "user":
        return None
    # The crate's directory is not always its package name: user/libnawah-text is `nawah-text`.
    name = parts[1].replace("_", "-")
    return "nawah-text" if name == "libnawah-text" else name


def host_suite_of(wt: Path, test_id):
    """The host suite of tools/project.py that holds `test_id`, or None."""
    r = subprocess.run(["python3", str(wt / "tools" / "project.py"), "host-suite-of", test_id],
                       cwd=wt, capture_output=True, text=True)
    return r.stdout.strip() or None if r.returncode == 0 else None


def suite_of(target, test_id):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    for suite, cases in t["suites"].items():
        if any(c["id"] == test_id for c in cases):
            return suite
    return None


def run_killers(wt: Path, env, target, killers, budget, fairness=False):
    """Returns (killed_by, results, timed_out_tid). Every case runs through its suite entry (the
    strong oracle); a missing artifact (exit 20) is SKIPPED and a lab failure (QEMU died,
    LAB_ERROR) is ERROR — neither is a kill. A declared killer that times out is a kill of the
    mutant (the hang is the mutated kernel's); a timeout in the fairness sweep is an
    infrastructure overrun, never a kill."""
    results = {}
    pyproj = ["python3", str(wt / "tools" / "project.py")]
    for tid in killers:
        suite = suite_of(target, tid)
        if suite is None:
            # A host case (M5 gate: libui's unit tests, the text conformance suites) runs on the
            # worktree through the same driver; project.py knows its suite.
            host_suite = host_suite_of(wt, tid)
            if host_suite is None:
                results[tid] = "SKIPPED"
                continue
            cmd = pyproj + ["test", "--target", "host", "--suite", host_suite, "--only", tid]
        else:
            cmd = pyproj + ["test", "--target", target, "--suite", suite, "--only", tid]
        try:
            r = run_bounded(cmd, wt, env, budget, "test", tid)
        except MutantTimeout as ex:
            if fairness:
                raise InfraError(f"watchdog {budget.seconds}s fired in the fairness sweep at {ex.tid}; "
                                 "the survivor cannot be decided")
            results[tid] = "TIMEOUT"
            return [tid], results, tid
        if r.returncode == 0:
            results[tid] = "PASS"
        elif r.returncode == 20 or "no artifact" in r.stdout:
            results[tid] = "SKIPPED"
        elif "LAB_ERROR" in r.stdout:
            # The emulator died twice: no verdict on the mutant from this case (never a kill).
            results[tid] = "ERROR"
        else:
            results[tid] = "FAIL"
            # One failing declared killer is the verdict; no budget is spent on the rest.
            return [tid], results, None
    return [t for t, v in results.items() if v == "FAIL"], results, None


def all_cases(target):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    ids = ["TST-M1-BOOT"]
    for cases in t["suites"].values():
        ids += [c["id"] for c in cases if c["id"] not in ("TST-M1-BOOT",)]
    return ids


def merge_reports(paths, out):
    """--merge: combine the reports of the four M5 shards into the gate's one report and verdict.
    Duplicate ids or an unreadable report are an infrastructure error (exit 2), never a pass."""
    entries = {}
    for p in paths:
        try:
            rep = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError) as ex:
            print(f"merge: cannot read {p}: {ex}", flush=True)
            return EXIT_INFRA
        for m in rep.get("mutants", []):
            mid = m.get("id")
            if not mid:
                print(f"merge: {p}: a mutant has no id", flush=True)
                return EXIT_INFRA
            if mid in entries:
                print(f"merge: {mid} appears in more than one shard", flush=True)
                return EXIT_INFRA
            entries[mid] = m
    report = {"threshold": THRESHOLD, "target": "pc-qemu",
              "mutants": [entries[k] for k in sorted(entries, key=lambda s: int(s[1:]))],
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "merged": True}
    finalize(report, partial=False)
    verdict = bool(report["valid"]) and report["ratio"] >= THRESHOLD and not report["surviving_security"]
    code = EXIT_INFRA if report["infra_error"] else (EXIT_OK if verdict else EXIT_GATE)
    report["exit_code"] = code
    write_report(REPO / Path(out), report)
    print(f"\n{'OK' if verdict else 'FAIL'}: merged {report['killed']}/{report['valid']} valid mutants killed "
          f"({report['ratio']:.1%}, threshold {THRESHOLD:.0%}); survived={report['survived']}; "
          f"surviving_security={report['surviving_security']}; invalid={report['invalid']}; "
          f"infra_error={report['infra_error']}; timeout_killed={report['timeout_killed']}; "
          f"report={out}; exit={code}", flush=True)
    return code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="pc-qemu")
    ap.add_argument("--report", default=None, help="default: mutants-mN-report.json for the selected gate")
    ap.add_argument("--progress", default=None, help="incremental JSONL (default: from the report name)")
    ap.add_argument("--only", help="comma-separated mutant ids")
    ap.add_argument("--from", dest="from_id", help="first mutant id of a range, inclusive (e.g. M92)")
    ap.add_argument("--to", dest="to_id", help="last mutant id of a range, inclusive (e.g. M101)")
    ap.add_argument("--stage", choices=["M2", "M3", "M4", "M5"], help="run only the mutants of one gate (M01-M29 = M2, M30-M49 = M3, M50-M81 = M4, M82.. = M5)")
    ap.add_argument("--check", action="store_true", help="apply/revert each patch and cargo check on the host target only")
    ap.add_argument("--watchdog-seconds", type=int, default=WATCHDOG_S,
                    help="per-mutant safety ceiling (preparatory 600 s; final max(300, 2 x p95))")
    ap.add_argument("--merge", nargs="+", metavar="REPORT", help="merge shard reports and exit")
    a = ap.parse_args()
    if a.merge:
        return merge_reports(a.merge, a.report or "build/mutants-m5-report.json")

    mutants = [m for m in MUTANTS if (not a.only or m[0] in a.only.split(","))
               and (not a.stage or stage_of(m[0]) == a.stage)]
    if a.from_id:
        lo = int(a.from_id[1:])
        mutants = [m for m in mutants if int(m[0][1:]) >= lo]
    if a.to_id:
        hi = int(a.to_id[1:])
        mutants = [m for m in mutants if int(m[0][1:]) <= hi]
    if not mutants:
        print("no mutant selected", flush=True)
        return EXIT_GATE
    rp = REPO / Path(a.report or report_name(a.stage))
    pp = REPO / Path(a.progress or progress_name(rp))
    previous = {} if a.check else previous_entries(pp, rp)

    def _stop(signum, frame):
        raise KeyboardInterrupt

    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _stop)
        except (ValueError, OSError):
            pass

    tmp = Path(tempfile.mkdtemp(prefix="nawah-mutants-"))
    wt = tmp / "wt"
    scratch = tmp / "scratch-evidence"
    scratch.mkdir()
    report = {"threshold": THRESHOLD, "target": a.target, "mutants": [],
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "watchdog_s": a.watchdog_seconds, "partial": True}

    def finish_one(entry):
        report["mutants"].append(entry)
        finalize(report, partial=True)
        append_progress(pp, entry)
        write_report(rp, report)

    infra = False
    interrupted = False
    try:
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(wt), "HEAD"], cwd=REPO, check=True)
        env = dict(os.environ, NAWAH_ROOT=str(wt), NAWAH_SCRATCH_EVIDENCE=str(scratch), NAWAH_QEMU_TIMEOUT_S="90")
        env.setdefault("RUSTUP_TOOLCHAIN", os.environ.get("RUSTUP_TOOLCHAIN", ""))
        if not env["RUSTUP_TOOLCHAIN"]:
            del env["RUSTUP_TOOLCHAIN"]
        for m in mutants:
            mid, rel, old, new, killers, note = m
            if mid in previous:
                entry = dict(previous[mid])
                entry["resumed"] = True
                report["mutants"].append(entry)
                finalize(report, partial=True)
                write_report(rp, report)
                print(f"{mid}: resumed {entry.get('status')} [{entry.get('seconds', '?')}s]", flush=True)
                continue
            t0 = time.time()
            entry = {"id": mid, "file": rel, "note": note, "killers": killers, "security": security_of(mid)}
            print(f"{mid}: start (watchdog {a.watchdog_seconds}s) ({note})", flush=True)
            reset(wt)
            try:
                apply(wt, m)
            except RuntimeError as ex:
                entry.update(status="invalid", reason=str(ex), seconds=round(time.time() - t0, 1))
                finish_one(entry)
                print(f"{mid}: INVALID [{entry['seconds']}s] ({ex}) ({note})", flush=True)
                continue
            if a.check:
                crate = crate_of(rel)
                if crate is None:
                    cmd = ["cargo", "check", "--offline", "--manifest-path", "kernel/Cargo.toml", "--target", "x86_64-unknown-linux-gnu",
                           "--features", "ktest", "--target-dir", str(tmp / "check-target")]
                else:
                    cmd = ["cargo", "check", "--offline", "--profile", "app", "-p", crate, "--target", "x86_64-unknown-linux-gnu",
                           "--target-dir", str(tmp / "check-target")]
                r = sh(cmd, wt, dict(env, NAWAH_BUILD_ID="mutcheck"))
                ok = r.returncode == 0
                entry.update(status="compiles" if ok else "invalid", seconds=round(time.time() - t0, 1))
                if not ok:
                    entry["reason"] = r.stdout[-1500:]
                finish_one(entry)
                print(f"{mid}: {'compiles' if ok else 'DOES NOT COMPILE'} [{entry['seconds']}s] ({note})", flush=True)
                continue
            budget = Budget(a.watchdog_seconds)
            try:
                benv = dict(env, NAWAH_BUILD_ID=f"mut{mid.lower()}", NAWAH_OUT=str(wt / "build" / a.target),
                            NAWAH_APPS_DIR=str(wt / "build" / a.target / "apps"))
                (wt / "build" / a.target / "apps").mkdir(parents=True, exist_ok=True)
                need_release = "TST-M1-BOOT" in killers
                build_ok = True
                steps = [app_step(n) for n in APPS] + [(KTEST_STEP, KTEST_OUT, "NAWAH-KTEST.EFI")]
                if need_release:
                    steps.append((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"))
                for step, out, name in steps:
                    r = run_bounded(step, wt, benv, budget, "build")
                    if r.returncode != 0:
                        build_ok = False
                        entry["reason"] = r.stdout[-2000:]
                        break
                    shutil.copy(wt / out, wt / "build" / a.target / name)
                if not build_ok:
                    entry.update(status="invalid", seconds=round(time.time() - t0, 1))
                    finish_one(entry)
                    print(f"{mid}: INVALID (does not build) [{entry['seconds']}s] ({note})", flush=True)
                    continue
                (wt / "build" / a.target / "build-id.txt").write_text(benv["NAWAH_BUILD_ID"] + "\n")
                killed_by, results, timed = run_killers(wt, env, a.target, killers, budget)
                declared_miss = not killed_by
                if not killed_by:
                    # Be fair before declaring a survivor: build the remaining artifacts and run
                    # everything the suites have. A watchdog overrun here is infrastructure, not a
                    # kill: it cannot decide the survivor.
                    rest = [c for c in all_cases(a.target) if c not in killers]
                    for step, out, name in ((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"), (NEG_STEP, NEG_OUT, "NAWAH-NEG.EFI")):
                        if (wt / "build" / a.target / name).exists() and name == "NAWAH.EFI" and need_release:
                            continue
                        r = run_bounded(step, wt, benv, budget, "build")
                        if r.returncode == 0:
                            shutil.copy(wt / out, wt / "build" / a.target / name)
                    more_killed, more, more_timed = run_killers(wt, env, a.target, rest, budget, fairness=True)
                    results.update(more)
                    killed_by = more_killed
                    timed = timed or more_timed
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
                status = "timeout-killed" if timed else ("killed" if killed_by else "survived")
                entry.update(status=status, killed_by=killed_by, results=results,
                             timed_out=bool(timed), seconds=round(time.time() - t0, 1))
            except MutantTimeout as ex:
                entry.update(status="timeout-killed", timed_out=True, killed_by=[ex.tid] if ex.tid else [],
                             results={ex.tid: "TIMEOUT"} if ex.tid else {},
                             reason=f"watchdog {a.watchdog_seconds}s fired during {ex.tid}",
                             seconds=round(time.time() - t0, 1))
            except InfraError as ex:
                infra = True
                entry.update(status="infra-error", reason=str(ex), seconds=round(time.time() - t0, 1))
            finish_one(entry)
            if entry["status"] == "timeout-killed":
                print(f"{mid}: timeout-killed by {','.join(entry['killed_by']) or '?'} "
                      f"[{entry['seconds']}s] ({note})", flush=True)
            elif entry["status"] == "killed":
                print(f"{mid}: killed by {','.join(entry['killed_by'])} [{entry['seconds']}s] ({note})", flush=True)
            elif entry["status"] == "survived":
                print(f"{mid}: SURVIVED [{entry['seconds']}s] ({note})", flush=True)
            else:
                print(f"{mid}: {entry['status'].upper()} [{entry['seconds']}s] ({entry.get('reason', '')})", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        infra = True
        report["status"] = "interrupted"
    except BaseException as ex:
        interrupted = True
        infra = True
        report["status"] = "error"
        report["error"] = repr(ex)
    finally:
        try:
            reset(wt)
        except Exception:
            pass
        subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=REPO)
        shutil.rmtree(tmp, ignore_errors=True)
        selected = {m[0] for m in mutants}
        done = {e["id"] for e in report["mutants"]}
        partial = interrupted or done != selected
        finalize(report, partial=partial)
        write_report(rp, report)

    if a.check:
        if interrupted:
            print(f"\nINFRA-ERROR: the check was interrupted; partial report={rp}", flush=True)
            return EXIT_INFRA
        bad = [m["id"] for m in report["mutants"] if m["status"] == "invalid"]
        good = len(report["mutants"]) - len(bad)
        print(f"\n{'OK' if not bad else 'FAIL'}: {good}/{len(report['mutants'])} mutants apply and type-check"
              + (f"; invalid: {bad}" if bad else ""), flush=True)
        return EXIT_OK if not bad else EXIT_GATE
    verdict = bool(report["valid"]) and report["ratio"] >= THRESHOLD and not report["surviving_security"]
    code = EXIT_INFRA if (infra or report["infra_error"] or report["partial"]) else (EXIT_OK if verdict else EXIT_GATE)
    report["exit_code"] = code
    write_report(rp, report)
    print(f"\n{'OK' if verdict else 'FAIL'}: {report['killed']}/{report['valid']} valid mutants killed "
          f"({report['ratio']:.1%}, threshold {THRESHOLD:.0%}); survived={report['survived']}; "
          f"surviving_security={report['surviving_security']}; invalid={report['invalid']}; "
          f"timeout_killed={report['timeout_killed']}; infra_error={report['infra_error']}; "
          f"declared_killers_missed={report['declared_killers_missed']}; "
          f"report={rp}; progress={pp}; exit={code}", flush=True)
    if report["infra_error"]:
        print("infra-error: the run is not a gate verdict (exit 2)", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
