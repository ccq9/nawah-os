#!/usr/bin/env python3
# Origin: Sol OS (d54f0a5) `tests/mutants.py` (ADR-0002 item 4), adapted here to nawah-os's stages,
# lab driver and evidence rules; re-verified by TST-M0-005 and by every gate's mutation run.
"""TST-M2-MUTANTS (REQ-M2-014), TST-M3-MUTANTS (REQ-M3-010, WP-22) and TST-M4-MUTANTS
(REQ-M4-010, WP-31): seeded-defect mutation testing of the kernel and the system services
against the guest suites — M01..M29 cover arch/, mm/ and sync (M1/M2 suites); M30..M49 cover the
M3 modules (scheduler, objects, syscalls, ELF loader, MMIO window, TLB shootdown, SMP placement,
virtio-blk, FAT32, VFS) and are killed by M3 cases, including the host checks a case runs on the
disk image; M50 onwards cover the M4 modules (process/wait syscalls, tokens, device objects and
polling, system_info, dir_list, and the user-space services svcmgr, authd, configd, netd, sh)
and are killed by M4 cases, console sessions included; M82 onwards cover the M5 modules (displayd,
inputd, sessiond, libui, libnawah-text, and from M92 the kernel's process kill, frame clear and
mouse path and the manager's watchdog; TST-M5-MUTANTS, WP-38) and are killed by M5 cases, the
host suites included (libui's unit tests, the text conformance suites). `--stage` selects one
group; `--shard k/N` runs one shard of it, and NAWAH_GATE_SHARDS=N makes the gate's command merge
the N shard reports into its one verdict (WP-98). A mutant in SECURITY undoes a security fix: the run fails if it survives, whatever the
ratio.

Each mutant is one deliberate defect (a textual patch that must match exactly once). The runner
works in a detached git worktree of HEAD so the real checkout, its build/ directory and the
evidence records are never touched: evidence of the mutant runs goes to a scratch directory
(NAWAH_SCRATCH_EVIDENCE) and tools/project.py attaches nothing in that mode. The worktree holds
every top-level tree of HEAD but evidence/, and a worktree a killed run left is removed at the
next start (WP-130).

For each mutant: apply, build only the artifacts its killer tests need, run those tests
(`project.py boot` for TST-M1-BOOT, `project.py test --only` for every other case). A mutant is
  killed   - at least one killer test FAILs (or times out) ;
  survived - every killer test PASSes; the whole M1+M2 suites are then run before the verdict ;
  invalid  - the mutant does not compile (excluded from the ratio; a defect that cannot build is
             not a defect the suite had to catch).
PASS = kill ratio >= 0.95 over valid mutants. `--check` only applies/reverts the patches and
type-checks them on the host target (what this sandbox can do without the UEFI toolchain).
"""
import argparse, json, os, re, subprocess, sys, tempfile, time, shutil
from pathlib import Path

try:
    import fcntl
except ImportError:  # no flock off POSIX: every lock reads held, so no worktree is ever removed
    fcntl = None

REPO = Path(__file__).resolve().parents[1]
# Where a run makes its temporary directory (`nawah-mutants-*`, holding the worktree `wt`, the
# scratch evidence and the run's lock); only there are the leftovers of a killed run removed.
TMP_ROOT = Path(tempfile.gettempdir())
PREFIX = "nawah-mutants-"
THRESHOLD = 0.95
# Every gate the harness knows (argparse --stage); each must have a HOST_SUITES gate suite that
# mutants.yml runs (TST-M0-005 GateMapping, WP-90).
STAGES = ("M2", "M3", "M4", "M5", "M6")

# WP-98: a gate in N shards. `--shard k/N` runs the selected mutants whose number is k-1 modulo N
# and writes its report, with its identity, to <report stem>.shards/shard-k-of-N.json; with
# NAWAH_GATE_SHARDS=N in its environment the gate's own command runs no mutant and merges the N
# reports into the gate's one verdict, or refuses (MERGE_REFUSED, no verdict line, no report) a set
# that is not exactly the stage's mutants, each decided once, by this very run.
GATE_SHARDS_ENV = "NAWAH_GATE_SHARDS"
SHARD_RULE = "int(id[1:]) mod N == k-1"
MERGE_REFUSED = 3
DECIDED = ("killed", "survived", "invalid")

# The per-case QEMU timeout while a mutant runs. It bounds a mutant that hangs a case, but it
# must not fail a case that is merely slow: the slowest M5 case on the clean tree is
# TST-M5-ELEVATE at ~124 s (CI verify 41232334352, 2026-10-31). The old blanket 90 s failed
# ELEVATE on every mutant in the fairness sweep and counted that infrastructure timeout as a
# kill (run 41232332567). 180 s cleared it then; the slowest committed ELEVATE run takes 156 s
# start to finish (evidence/20261109T104517Z-dece70c2-001, 2026-11-09) and WP-38 adds phase 3i
# (a frozen service, a pointer flood, a second unlock), so 300 s keeps the margin and still
# bounds a real hang.
MUTANT_CASE_TIMEOUT_S = 300


def mutant_build_id(mid: str) -> str:
    """The build identity a mutant's kernel carries. TST-M5-DISPLAY-BOOT decodes the frame's
    build-id bar one hex digit per cell and compares it to BUILD_ID, so the id must be all hex
    (`mutm94` decoded to `000094`, bar_ok=0, and the sweep read that failure as a kill). The
    mutant number in 12 hex digits is unique and decodes cleanly."""
    return f"{int(mid[1:]):012x}"

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
     ["TST-M3-RIGHTS-DENIED"], "SECURITY: channel_write ignores the WRITE right"),
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
     "        for k in (0..self.fats).rev() {\n            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;",
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
     ["TST-M4-WAIT-TIMEOUT"], "SECURITY: any handle mints tokens (the authority check removed; the waiter app probes it)"),
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
     ["TST-M4-LOGIN"], "SECURITY: the authority is never handed to auth"),
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
     ["TST-M4-SHELL-SVC"], "SECURITY: a service connects to any service, declared or not"),
    ("M68", "user/apps/authd/src/main.rs",
     "        let ok = ct_eq(&dk, &u.hash);", "        let ok = ct_eq(&dk, &u.hash) || !dk.is_empty();",
     ["TST-M4-LOGIN", "TST-M4-SHELL-LOGIN"], "SECURITY: any password is accepted"),
    ("M69", "user/apps/authd/src/main.rs",
     "        if self.fails < MAX_FAILS {", "        if self.fails < MAX_FAILS + 1000 {",
     ["TST-M4-LOGIN"], "SECURITY: the attempt limit never delays"),
    ("M70", "user/apps/authd/src/main.rs",
     "    fn close_session(&mut self, slot: usize) {\n        let s = &mut self.sessions[slot];\n        libnawah::token_revoke(s.token);",
     "    fn close_session(&mut self, slot: usize) {\n        let s = &mut self.sessions[slot];",
     ["TST-M4-SESSION-LOCK"], "SECURITY: LOGOUT does not revoke the token"),
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
     ["TST-M4-AUTHZ-DENIED"], "SECURITY: any token may write the device store"),
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
     ["TST-M4-NET-NO-INTERNET"], "SECURITY: the no-internet policy is not applied"),
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
     ["TST-M5-NARRATOR-AUTHORITY"], "SECURITY: any client may become the narrator (WP-43 M2 undone)"),
    ("M83", "user/apps/displayd/src/main.rs",
     "                if self.surfaces.iter().filter(|s| used(s)).count() >= CLIENT_SURFACES {",
     "                if self.surfaces.iter().filter(|s| used(s)).count() > CLIENT_SURFACES {",
     ["TST-M5-CLIENT-LIMITS"], "SECURITY: a client gets one surface more than its share (WP-43 S-7, boundary)"),
    ("M84", "user/apps/displayd/src/main.rs",
     "                if mine >= CLIENT_WINDOWS {\n                    out.put(b\"ERR LIMIT\");\n                    return false;\n                }",
     "",
     ["TST-M5-CLIENT-LIMITS"], "SECURITY: no per-client window limit (WP-43 S-7 undone)"),
    ("M85", "user/apps/displayd/src/main.rs",
     "const SESSION_RESERVE: usize = 2;", "const SESSION_RESERVE: usize = 0;",
     ["TST-M5-CLIENT-LIMITS"], "SECURITY: no surfaces or windows kept for the session (WP-43 S-7)"),
    ("M86", "user/apps/displayd/src/main.rs",
     "        if !self.visible(wi) {\n            return false;\n        }\n        let area = w.client().intersect(self.screen);",
     "        let area = w.client().intersect(self.screen);",
     ["TST-M5-LIST-HASH-HELD"], "SECURITY: LIST hashes a held or minimised window's place (WP-43 M3 undone)"),
    ("M87", "user/apps/displayd/src/main.rs",
     "        if !self.locked {\n            self.composed += 1;\n        }",
     "        self.composed += 1;",
     ["TST-M5-LIST-HASH-HELD"], "SECURITY: STATUS counts the held screen's redraws, one per key typed (WP-43 M3 undone)"),
    ("M88", "user/apps/sessiond/src/main.rs",
     "                if self.dialog.element(i).role != Role::Password {\n                    self.announce(b\"change\", Some(i));\n                }",
     "                self.announce(b\"change\", Some(i));",
     ["TST-M5-AUTH-INPUT-ISOLATED"], "SECURITY: the password field announces every keystroke (WP-43 M2 undone)"),
    ("M89", "user/apps/sessiond/src/main.rs",
     "        self.take_keyboard();\n        if self.owner != Owner::Session {\n            self.elevate_end(b\"ERR UNAVAILABLE\", now);\n            return;\n        }\n        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);\n        self.show(Screen::Elevate, None);",
     "        let mut r = [0u8; 64];\n        self.display_call(b\"LOCKED\", &[], &mut r);\n        self.show(Screen::Elevate, None);\n        self.take_keyboard();\n        if self.owner != Owner::Session {\n            self.elevate_end(b\"ERR UNAVAILABLE\", now);\n            return;\n        }",
     ["TST-M5-ELEVATE"], "SECURITY: the elevation prompt is shown before the keyboard is taken (WP-41 S1 undone, order swapped)"),
    ("M90", "user/apps/inputd/src/main.rs",
     "                if name == b\"display\" && self.clients[ci].ident() != b\"display\" {\n                    out.put(b\"ERR ACCESS\");\n                    return;\n                }",
     "",
     ["TST-M5-INPUT-NAME-RESERVED"], "SECURITY: any client may register the name `display` (WP-43 S-5 undone)"),
    ("M91", "user/libui/src/lib.rs",
     "                        if e.role == Role::Password {\n                            s[..e.text_len].fill(BULLET);\n                        }",
     "",
     ["TST-M5-UI-UNIT"], "SECURITY: a password field draws its characters instead of bullets"),
    # ---- M5 gate, phase 2 (WP-38, owner-approved table of 2026-10-28): 30 mutants over the
    # six categories (check removal <= 6, condition flip <= 6, boundary shift <= 5, constant
    # <= 4, assignment drop <= 4, order swap >= 5). Replacements approved for the original
    # M99, M104, M110, M112, M113 and M120 sites, whose first forms were equivalent, absent
    # from the code, or would not compile; each stays in its file and category.
    ("M92", "user/apps/displayd/src/main.rs",
     "        !w.minimized && (!self.locked || self.clients[w.owner].session)\n    }\n\n    /// Whether the client area",
     "        w.minimized && (!self.locked || self.clients[w.owner].session)\n    }\n\n    /// Whether the client area",
     ["TST-M5-WINDOW-STATES"], "visible() inverted: minimised windows shown, shown ones hidden (condition flip)"),
    # M93 was `cyclable()`'s lock guard (check removal). It is EQUIVALENT: cyclable is reached
    # only from the Alt+Tab handler in on_key, which runs only while displayd holds the keyboard
    # -- i.e. while unlocked, where `!self.locked` is already true. No test can distinguish it,
    # and the lock-holds-windows property is enforced by visible() (M86, M92). Dropped rather
    # than padded with a redundant mutant (run 41232332567, 2026-10-31).
    # The first form `(0..k)` -> `(0..=k)` was equivalent: j==k is the window itself, for which
    # `ow.owner == w.owner` holds, so `.all()` is unchanged (survived every test, run 41232332567,
    # 2026-10-31). `(1..k)` skips the topmost window instead: a top window of another client that
    # covers this one is no longer seen, so owns_client_area wrongly reports the area owned and
    # LIST hashes it rather than `-`.
    ("M94", "user/apps/displayd/src/main.rs",
     "        (0..k).all(|j| {\n            let o = self.order[j];",
     "        (1..k).all(|j| {\n            let o = self.order[j];",
     ["TST-M5-LIST-HASH-HELD"], "owns_client_area skips the topmost window, so a covered client area reads as its own (boundary shift)"),
    ("M95", "user/apps/displayd/src/main.rs",
     "        for si in 0..MAX_SURFACES {\n            if self.surfaces[si].used && self.surfaces[si].owner == ci {\n                self.destroy_surface(si);\n            }\n        }\n        if self.clients[ci].unresponsive {",
     "        if self.clients[ci].unresponsive {",
     ["TST-M5-WINDOW-STATES"], "SECURITY: a gone client's surfaces are kept mapped (assignment drop: the destroy loop)"),
    ("M96", "user/apps/displayd/src/main.rs",
     "const CLIENT_WINDOWS: usize = 4;", "const CLIENT_WINDOWS: usize = 5;",
     ["TST-M5-CLIENT-LIMITS"], "SECURITY: one window over the share (constant)"),
    # M97 was LOGOUT's `self.locked = true;` (order swap: the hold first). It is EQUIVALENT:
    # the session sends LOGOUT only from the lock screen (both sign_out callers run in
    # State::Locked), after LOCKED on the same channel (re-sent first on a reconnect), and
    # displayd starts locked when a session is in its manifest and re-locks when the session is
    # lost (main.rs 1102). So `locked` is already true whenever LOGOUT arrives and the line is
    # defence in depth with no reachable effect. Dropped (survived every test, run 41232332567).
    ("M98", "user/apps/sessiond/src/main.rs",
     "        self.state = State::Locked;\n        if self.elevation.is_some() {\n            self.elevate_end(b\"ERR CANCELLED\", now);\n            self.want_display = false;\n        }\n        self.changes += 1;",
     "        if self.elevation.is_some() {\n            self.elevate_end(b\"ERR CANCELLED\", now);\n            self.want_display = false;\n        }\n        self.changes += 1;\n        self.state = State::Locked;",
     ["TST-M5-LOCK-SURVIVES", "TST-M5-ELEVATE"], "SECURITY: lock(): the state is set after the prompt ends, so ending the prompt releases the desktop in between (order swap)"),
    ("M99", "user/apps/sessiond/src/main.rs",
     "        let op = AuthOp::Login { name, len: nn };\n        let sent = self.auth_send(req.bytes(), false, op);",
     "        let op = AuthOp::Login { name, len: nn };\n        req.wipe();\n        let sent = self.auth_send(req.bytes(), false, op);",
     ["TST-M5-AUTH-INPUT-ISOLATED", "TST-M5-LOGIN-SCREEN"], "SECURITY: the sign-in request is wiped before it is sent: LOGIN goes out empty (order swap of wipe and send)"),
    # M100's first form dropped the stale-answer check `e.n == n` in elevate_answer. It was
    # EQUIVALENT: elevate_request refuses ERR BUSY while an administrator's answer is awaited,
    # so no answer can ever arrive while another elevation is current, and the check is defence
    # in depth with no reachable effect (survived run 41281612670). The guard that does the work
    # is mutated instead, same file and category (check removal, security).
    ("M100", "user/apps/sessiond/src/main.rs",
     "        if self.elevation.is_some() || self.elevate_answer_pending() {\n            return Some(b\"ERR BUSY\");",
     "        if self.elevation.is_some() {\n            return Some(b\"ERR BUSY\");",
     ["TST-M5-ELEVATE"], "SECURITY: a new elevation is accepted while an administrator's answer for an ended one is awaited (check removal; WP-41 C1 undone)"),
    ("M101", "user/apps/sessiond/src/main.rs",
     "        self.state = State::Locked;\n        if self.elevation.is_some() {",
     "        self.state = State::Locked;\n        if self.elevation.is_none() {",
     ["TST-M5-ELEVATE"], "SECURITY: the secure attention sequence no longer ends an elevation prompt (condition flip)"),
    # M102 was `self.elevate_seq += 1;` (assignment drop: every elevation numbered alike). It is
    # EQUIVALENT for the reason M100's first form was: the number is compared only by an answer
    # that cannot meet a newer elevation, ERR BUSY having refused it. Dropped (survived run
    # 41281612670); the BUSY guard is covered by M100.
    ("M103", "user/apps/sessiond/src/main.rs",
     "const RELEASE_WAIT: u64 = 1000;", "const RELEASE_WAIT: u64 = 0;",
     ["TST-M5-FOCUS-AFTER-RESTART", "TST-M5-LOCK-DISPLAY-DOWN", "TST-M5-ELEVATE"], "no wait before the keyboard is handed over (constant)"),
    ("M104", "user/apps/sessiond/src/main.rs",
     "                    if now >= deadline {\n                        return Err(ERR_TIMED_OUT);",
     "                    if now >= deadline.saturating_add(REQUEST_DEADLINE) {\n                        return Err(ERR_TIMED_OUT);",
     ["TST-M5-SESSION-DEADLINE", "TST-M5-SESSION-HANG"], "a service request times out after twice its deadline (boundary shift). The declared LOCK/UNLOCK-AUTH-HANG cases do not measure the deadline since auth went async (session.md v1.2); the request deadline is observed by SESSION-DEADLINE (window [4900,6000] ticks) and SESSION-HANG. Confirmed in the sweep of run 41232332567."),
    ("M105", "user/apps/sessiond/src/main.rs",
     "            // The screen is released only to an unlocked desktop; a lock keeps it held.\n            if self.state == State::Unlocked {",
     "            // The screen is released only to an unlocked desktop; a lock keeps it held.\n            if self.state == State::Locked {",
     ["TST-M5-ELEVATE", "TST-M5-LOCK-SURVIVES"], "SECURITY: ending a prompt releases the screen while locked and keeps it held when unlocked (condition flip)"),
    ("M106", "user/apps/inputd/src/main.rs",
     "        if &c.name[..c.name_len] == b\"session\" {\n            self.focus = None;\n        }\n        self.clients[ci] = NO_CLIENT;",
     "        self.clients[ci] = NO_CLIENT;",
     ["TST-M5-SESSION-LOSS"], "SECURITY: a lost session leaves the focus with whoever had it (check removal; input.md v2.2 undone)"),
    ("M107", "user/apps/inputd/src/main.rs",
     "                if let Some(s) = self.session_client() {\n                    // v2.2: the session owns the keyboard from here (the releases of Ctrl\n                    // and Alt included) until it names another owner — a window that\n                    // imitates the sign-in screen never sees the sequence or what follows.\n                    self.focus = Some(self.clients[s].id);\n                    self.deliver(s, b\"SAK\");\n                }",
     "                if let Some(s) = self.session_client() {\n                    self.deliver(s, b\"SAK\");\n                }",
     ["TST-M5-INPUT-ROUTE", "TST-M5-AUTH-INPUT-ISOLATED"], "SECURITY: the secure attention sequence tells the session but leaves the keyboard with the focused client (condition flip: the owner no longer changes)"),
    ("M108", "user/apps/inputd/src/main.rs",
     "                self.combo_armed = self.mods == (MOD_SHIFT | MOD_ALT);\n            } else {\n                self.mods &= !bit;",
     "                self.combo_armed = false;\n                if self.mods == (MOD_SHIFT | MOD_ALT) {\n                    self.toggle_layout();\n                }\n            } else {\n                self.mods &= !bit;",
     ["TST-M5-ARABIC-UI", "TST-M5-INPUT-ROUTE"], "the layout toggles on the press of the second modifier instead of on the release (order swap)"),
    ("M109", "user/apps/inputd/src/main.rs",
     "        } else if down {\n            // A real key press: not a clean Shift+Alt sequence.\n            self.combo_armed = false;\n        }",
     "        }",
     ["TST-M5-ARABIC-UI", "TST-M5-INPUT-ROUTE"], "a key pressed between Shift+Alt no longer disarms the toggle (assignment drop)"),
    ("M110", "user/apps/inputd/src/main.rs",
     "        let down = b & 0x80 == 0;", "        let down = b & 0x80 != 0;",
     ["TST-M5-INPUT-ROUTE"], "presses and releases swapped at the 0x80 bit (boundary shift)"),
    ("M111", "user/libui/src/lib.rs",
     "            KEY_TAB => return self.step(mods & MOD_SHIFT != 0),",
     "            KEY_TAB => return self.step(mods & MOD_SHIFT == 0),",
     ["TST-M5-UI-UNIT"], "Tab goes back and Shift+Tab forward (condition flip)"),
    ("M112", "user/libui/src/lib.rs",
     "            // A password field is described without its value (v1.1).\n            Role::TextField | Role::Value => {",
     "            // A password field is described without its value (v1.1).\n            Role::TextField | Role::Value | Role::Password => {",
     ["TST-M5-UI-UNIT"], "SECURITY: the narrator's description of a password field carries its value (check removal of the role exclusion)"),
    ("M113", "user/libui/src/lib.rs",
     "        let next = if back {\n            (pos + n - 1) % n\n        } else {\n            (pos + 1) % n\n        };",
     "        let next = if back {\n            (pos + n - 1) % n\n        } else {\n            (pos + 2) % n\n        };",
     ["TST-M5-UI-UNIT"], "Tab skips one element (boundary shift of the focus step)"),
    ("M114", "user/libui/src/lib.rs",
     "                let forward = (code == KEY_RIGHT) != rtl;",
     "                let forward = (code == KEY_RIGHT) == rtl;",
     ["TST-M5-UI-UNIT"], "Left and Right swapped between LTR and RTL (order swap of the cursor's direction)"),
    ("M115", "user/libnawah-text/src/bidi.rs",
     "                L => return 0,\n                R | AL => return 1,",
     "                L => return 1,\n                R | AL => return 0,",
     ["TST-M5-BIDI"], "the first strong character sets the opposite paragraph level (condition flip)"),
    # The first form (dropping the `u16::MAX` guard in first_strong_level) was equivalent on the
    # suite: without the guard i becomes 65535, the loop ends at `to` and returns `default`
    # anyway (survived locally, 2026-10-31).
    ("M116", "user/libnawah-text/src/bidi.rs",
     "            if ci == ES && ca == EN && cb == EN {\n                self.cls[i] = EN;\n            } else if ci == CS",
     "            if ci == CS",
     ["TST-M5-BIDI"], "rule W4 drops its ES branch: a European separator between digits stays a separator (check removal)"),
    ("M117", "user/libnawah-text/src/shape.rs",
     "pub const JT_U: u8 = 0;\npub const JT_R: u8 = 1;", "pub const JT_U: u8 = 1;\npub const JT_R: u8 = 0;",
     ["TST-M5-SHAPING"], "non-joining and right-joining types swapped (constant)"),
    ("M118", "user/libnawah-text/src/layout.rs",
     "                pen += adv;\n                g += 1;", "                g += 1;",
     ["TST-M5-SHAPING"], "the pen does not advance: every glyph at the same x (assignment drop)"),
    # The first form (`gid <= end` → `< end` in the glyph-class table) survived locally: no test
    # vector has a glyph at the last gid of a class range (2026-10-31).
    ("M119", "user/libnawah-text/src/font.rs",
     "                    if (u16_at(d, ends + mid * 2)? as u32) < cp {\n                        lo = mid + 1;",
     "                    if (u16_at(d, ends + mid * 2)? as u32) <= cp {\n                        lo = mid + 1;",
     ["TST-M5-GLYPHS"], "cmap format 4: a code point equal to a segment's end code falls into the next segment (boundary shift)"),
    ("M120", "user/libnawah-text/src/raster.rs",
     "const TOL: i64 = ONE / 64;", "const TOL: i64 = ONE * 64;",
     ["TST-M5-GLYPHS"], "flattening tolerance of 64 px: every curve becomes one chord (constant)"),
    ("M121", "user/libnawah-text/src/tables.rs",
     "    (0x28, 0x29, true),\n    (0x29, 0x28, false),", "    (0x28, 0x29, false),\n    (0x29, 0x28, false),",
     ["TST-M5-BIDI"], "`(` is no longer an opening bracket: the parenthesis pair never matches in N0 (check removal of the pair; the table keeps its size, [_; 128])"),
    # The kernel's M5 code and the manager's watchdog (WP-38 action of 2026-10-19: "kill,
    # watchdog"; PLAN.md asks for every M5 unit). Each killer asserts the effect directly: the
    # killer app's exit code, KILL-EDGES' per-case exit codes, the frame census after the
    # compositor stops, the mouse's PTR events and packet count, the watchdog's service states.
    ("M122", "kernel/src/syscall/mod.rs",
     "        if !e.rights.contains(Rights::WRITE) {\n            return Err(ERR_ACCESS);\n        }\n        p\n    };\n    if let Some(pid) = obj.pid() {",
     "        p\n    };\n    if let Some(pid) = obj.pid() {",
     ["TST-M5-PROCESS-KILL"], "SECURITY: process_kill needs no WRITE: a watcher's read-only duplicate kills (killer exits 0xE4)"),
    ("M123", "kernel/src/sched/mod.rs",
     "                State::Blocked | State::BlockedUntil { .. } | State::Sleeping { .. } => {\n                    t.state = State::Ready;",
     "                State::BlockedUntil { .. } | State::Sleeping { .. } => {\n                    t.state = State::Ready;",
     ["TST-M5-PROCESS-KILL"], "a kill does not wake a thread blocked without a deadline (ECHO in channel_read never dies: 0xE8)"),
    # The kill points of TST-M5-KILL-EDGES (d) and (f) make these races deterministic; (a) and
    # (b) pass under both mutants (ktest.rs says so), so only (d) and (f) see them.
    ("M124", "kernel/src/sched/mod.rs",
     "        // ever (review 2026-10-19, K1). The caller's wait loop sees `killed()` and returns.\n        if kill_pending(s, i) {\n            return None;\n        }\n",
     "        // ever (review 2026-10-19, K1). The caller's wait loop sees `killed()` and returns.\n",
     ["TST-M5-KILL-EDGES"], "a process killed just before it blocks blocks for ever (K1 undone for blocks: kill_at_block)"),
    ("M125", "kernel/src/sched/mod.rs",
     "                    p.exit_code = Some(p.kill.unwrap_or(code));",
     "                    p.exit_code = Some(code);",
     ["TST-M5-KILL-EDGES"], "a process killed inside exit reports its own code, read as a clean stop (K2 undone: kill_at_exit=0x55)"),
    # Zero height rather than no call, so `i` stays used and the mutant builds warning-free.
    ("M126", "kernel/src/display.rs",
     "    fill(&i, 0, 0, i.width, i.height, 0x000000);",
     "    fill(&i, 0, 0, i.width, 0, 0x000000);",
     ["TST-M5-LOCK-DISPLAY-DOWN"], "SECURITY: the frame is not cleared when the last VMO over it goes: a dead compositor's last picture stays through the lock (display.md v1.5 undone; clears=1 but lit, spy_px != 0)"),
    # `&& false` rather than `false`, so `mouse` stays used.
    ("M127", "kernel/src/net.rs",
     "        let dev = if mouse {\n            MOUSE_OBJECT.lock().clone()",
     "        let dev = if mouse && false {\n            MOUSE_OBJECT.lock().clone()",
     ["TST-M5-MOUSE"], "the mouse's bytes go to the keyboard ring (no PTR event, packets=0)"),
    ("M128", "user/apps/svcmgr/src/main.rs",
     "                } else if req == b\"PONG\" {\n                    // The service answered the watchdog PING; it is alive (v1.7).\n                    self.services[i].awaiting_pong = false;\n",
     "                } else if req == b\"PONG\" {\n",
     ["TST-M5-SVC-WATCHDOG"], "a PONG is ignored: a healthy watchdogged service is killed as hung (pong is not ready:0)"),
    ("M129", "user/apps/svcmgr/src/main.rs",
     "                        if hung {\n                            self.services[i].wd_deadline = None;\n                            self.services[i].killing = true;\n                            if let Some(p) = self.services[i].process {\n                                libnawah::process_kill(p);\n                            }\n",
     "                        if hung {\n                            self.services[i].wd_deadline = None;\n                            self.services[i].killing = true;\n",
     ["TST-M5-SVC-WATCHDOG"], "SECURITY: the watchdog finds a service hung but never kills it, so it is never restarted (hung is not given_up:1:131072)"),
    # ---- M6 (WP-45 red team): the boot-mode gate (boot.md v1.1); SECURITY, killer is the
    # release image's TST-M6-INTERACTIVE-BOOT, run by the M6 gate (TST-M6-MUTANTS, WP-90); the
    # anchor guard of TST-M0-005 keeps each anchor unique.
    # `|| true` rather than `true`, so `ecx` stays used and the mutant builds warning-free.
    ("M130", "kernel/src/arch/x86_64/fwcfg.rs",
     "    ecx & CPUID_ECX_HYPERVISOR != 0",
     "    ecx & CPUID_ECX_HYPERVISOR != 0 || true",
     ["TST-M6-INTERACTIVE-BOOT"], "SECURITY: hypervisor_present forced true: without the hypervisor bit fw_cfg is still read, so phase 5 (-cpu qemu64,-hypervisor with the key) prints hv=1|key=ok, m1_done and exits 33 (its line requires hv=0, exit 0)"),
    ("M131", "kernel/src/bootmode.rs",
     "        Some(_) => Key::Invalid,",
     "        Some(_) => Key::Ok,",
     ["TST-M6-INTERACTIVE-BOOT"], "SECURITY: any key value selects the self-test: phases 2 (selftest=0) and 6 (selftest=10) print key=ok and m1_done (forbidden) and exit 33, not 0"),
    # `|| true` rather than `true`, so the code after the diverging block stays reachable for
    # the compiler and the mutant builds warning-free.
    ("M132", "kernel/src/kmain.rs",
     "        if mode.selftest() {",
     "        if mode.selftest() || true {",
     ["TST-M6-INTERACTIVE-BOOT"], "SECURITY: the interactive boot takes the self-test exit: phase 1 prints m1_done (forbidden) and exits 33, not 0 by the lab's quit"),
    # ---- M6 (WP-64 purge, M135; WP-73 revocation, M137): a restarted session ends the lost one's windows before its sign-in
    # screen (session.md v1.7), and auth revokes the sessions of a lost `session` client (auth.md
    # v1.2); SECURITY. M133, M134 and M136 stay reserved for WP-71. M135 skips the purge (the
    # condition never holds, `purge_restarted` stays referenced so the mutant builds
    # warning-free). M137 keeps the count and its trace line but no longer closes the session.
    ("M135", "user/apps/sessiond/src/main.rs",
     "                if self.conn_n[DISPLAY] == 1 && !self.purge_restarted() {",
     "                if self.conn_n[DISPLAY] == 0 && !self.purge_restarted() {",
     ["TST-M5-SESSION-LOSS"], "SECURITY: the restarted session shows its sign-in screen without LOGOUT to the compositor: no session|purge line, the spy keeps its window and is not told LOGGED_OUT, so phase 2 reads spy_after=ready:… and windows=2, not stopped:0x0 and windows=1"),
    ("M137", "user/apps/authd/src/main.rs",
     "                self.close_session(s);",
     "                let _ = s;",
     ["TST-M6-TOKEN-REVOKE"], "SECURITY: auth forgets nothing when the session client is lost (the trace still says revoked=1): the dead session's token stays alive under auth's handle, so tokens_after=2|revoked=0 and failed=session_token, not tokens_after=1|revoked=1|failed=none"),
    # ---- M6 (WP-67): displayd's start-up hold fails closed (display.md v1.12); SECURITY.
    # M133, M134 and M136 are reserved for WP-71. The mutant keeps every trace line and changes only the
    # decision: held only for a valid listing naming `session`, so every LIST failure starts
    # unheld (the pre-v1.12 behaviour) behind a line that still says locked=1. The killer judges
    # the screen itself: HOLDS answers locked=0 and the injected key (press and release) reaches the window.
    ("M147", "user/apps/displayd/src/main.rs",
     "    Some(line.ends_with(b\"locked=1\"))",
     "    Some(line.starts_with(b\"display|hold|source=manifest\") && line.ends_with(b\"locked=1\"))",
     ["TST-M6-HOLD-FAIL-CLOSED"], "SECURITY: a LIST failure starts the screen unheld while the trace says locked=1: case=reply and case=too_long read holds=OK locked=0 (forbidden) and keys=2 (press and release both reach the window), not locked=1 and keys=0"),
    # ---- M6 (WP-64): the purge fails closed (session.md v1.7); SECURITY. A listing the
    # session cannot read is taken as "not restarted": the sign-in screen comes without LOGOUT.
    ("M150", "user/apps/sessiond/src/main.rs",
     "            None => (None, b\"list_failure\"),",
     "            None => return true,",
     ["TST-M6-PURGE-FAIL-CLOSED"], "SECURITY: a LIST the session cannot read skips the purge: sub-cases reply, no_session_line, bad_count, too_long and closed read logout=-|order=screen_only|ok=0 (closed: exit 0xe5, no LOGOUT), the list_failure trace appears 0 times, not 5, and failed= names those five"),
    # ---- M6 (WP-46): jobs (syscall.md v1.13 §5); SECURITY, killer TST-M6-JOB-KILL. M151 drops the
    # WRITE check every job call shares (job_of): `contains(NONE)` is always true, so the check
    # never fires and the line stays warning-free. M152 places syscall 20's child in the root
    # instead of the caller's job. M153 removes the locked dead-job check in spawn_user_with
    # (`if false`, so `process` stays used); process_spawn_in's early check hides it from user
    # space, so its killer is part 1 of the case (ktest job_spawn_dead).
    ("M151", "kernel/src/syscall/mod.rs",
     "    if !Rights::contains(e.rights, Rights::WRITE) {",
     "    if !Rights::contains(e.rights, Rights::NONE) {",
     ["TST-M6-JOB-KILL"], "SECURITY: a job handle without WRITE creates, kills and spawns into its job: the app's read-only duplicate is not refused, so phase 1 fails (jobs|phase=1|types=fail, exit 0xe4), not exit=0x4a"),
    ("M152", "kernel/src/syscall/mod.rs",
     "    let job = job.unwrap_or_else(sched::current_job);",
     "    let job = job.unwrap_or_else(crate::object::job::root);",
     ["TST-M6-JOB-KILL"], "SECURITY: process_spawn puts the child in the root, not the caller's job: the grandchild started inside job A escapes job_kill(A), so phase 5 fails (jobs|phase=5|kill=fail, exit 0xf4), not exit=0x4a"),
    ("M153", "kernel/src/sched/mod.rs",
     "        if process.object.as_ref().is_some_and(|o| o.job().dead()) {",
     "        if false {",
     ["TST-M6-JOB-KILL"], "SECURITY: a process enters a killed job when a kill lands after spawn's early check: job_spawn_dead's spawn starts (refused=0|…|ok=0, |ktest|fail|), not refused=1|ok=1"),
    # ---- M6 (WP-68): the manifest errors (services.md v1.13); M157 and M159 SECURITY. M157 and
    # M158 turn the refusal back into the pre-v1.13 `break`: the file is closed (a second close
    # follows, harmless) and what was read is parsed, so the manager answers OK 1. M159 keeps
    # system_path referenced (`false &&`), so the mutant builds warning-free.
    ("M157", "user/apps/svcmgr/src/main.rs",
     "                return Err(LoadError::TooLarge);",
     "                break;",
     ["TST-M6-MANIFEST-TOO-LARGE"], "SECURITY: a manifest of 4096 bytes or more is truncated and accepted: case=4097 and case=4096 read reply=OK 1 (forbidden), list=A:… and again=ERR LOADED (forbidden), ok=0, failed=4097,4096,"),
    ("M158", "user/apps/svcmgr/src/main.rs",
     "                    return Err(LoadError::Io);",
     "                    break;",
     ["TST-M6-MANIFEST-TOO-LARGE"], "a manifest whose read fails at byte 1024 is accepted from what was read: case=io reads reply=OK 1 (forbidden), fired=1, again=ERR LOADED (forbidden), ok=0, failed=io,"),
    ("M159", "user/apps/svcmgr/src/main.rs",
     "            } else if !system_path(path) {",
     "            } else if false && !system_path(path) {",
     ["TST-M6-LOAD-OUTSIDE-SYSTEM"], "SECURITY: LOAD reads outside /SYSTEM/: case=outside reads reply=OK 1|started=1|ok=0 (forbidden reply=OK), the later LOADs answer ERR LOADED (forbidden), failed=outside,dotdot,dep_name,system,"),
    # ---- M6 (WP-77): displayd's boot channel keeps serving (display.md v1.13); killer
    # TST-M6-DISPLAYD-BOOT-LOOP; neither is SECURITY. M160 puts back the pre-v1.13 `Err(_) => {}`
    # for the discard only (`Err(ERR_BUFFER_TOO_SMALL) | Err(ERR_SHOULD_WAIT) => {}`, the 0xE8 arm
    # kept, so it builds warning-free). M161
    # removes the STOP arm of session_in_manifest: STOPPED falls to reason=error.
    ("M160", "user/apps/displayd/src/main.rs",
     "                Err(ERR_BUFFER_TOO_SMALL) => {\n                    if !libnawah::channel_discard(c.boot) {\n                        return EXIT_BOOT_READ;\n                    }\n                    libnawah::trace(b\"display|boot|discard=too_long\");\n                }\n                Err(ERR_SHOULD_WAIT) => {}\n",
     "                Err(ERR_BUFFER_TOO_SMALL) | Err(ERR_SHOULD_WAIT) => {}\n",
     ["TST-M6-DISPLAYD-BOOT-LOOP"], "a boot message longer than 64 bytes stays at the head of the queue and the loop spins on it: case=too_long_msg reads pong=0|holds=error:K_E_SVC_TIMEOUT|exit=0x20000|ok=0, the trace display|boot|discard=too_long is missing, failed=too_long_msg,"),
    ("M161", "user/apps/displayd/src/main.rs",
     "        Err(STOPPED) => {\n            libnawah::trace(b\"display|boot|stop=before_ready\");\n            return None;\n        }\n",
     "",
     ["TST-M6-DISPLAYD-BOOT-LOOP"], "a STOP before the LIST answer is read as a failed LIST: case=stop_first reads ready=1|exit=0x20000|ok=0, display|hold|source=list_failure|reason=error|locked=1 appears (forbidden), display|boot|stop=before_ready is missing, failed=stop_first,"),
    # ---- M6 (WP-78): config's WRITE scope at the authority layer (files.md v1.4, RSK-019); all
    # SECURITY (each reopens a write under /SYSTEM outside config's stores); killer
    # TST-M6-CONFIG-WRITE-SCOPE (the fileauth probe with config's mask READ|WRITE|TRANSFER).
    ("M162", "kernel/src/syscall/mod.rs",
     "    if write && !vfs::is_config_store(path) {",
     "    if false && write && !vfs::is_config_store(path) {",
     ["TST-M6-CONFIG-WRITE-SCOPE"], "SECURITY: WRITE alone decides again: step 40 opens /SYSTEM/SERVICES.TXT for writing, probe=0x28, then |ktest|fail| (forbidden)"),
    ("M163", "kernel/src/fs/vfs.rs",
     "        Ok(n) => n.starts_with(b\"CFG\") && matches!(&n[8..], b\"A  \" | b\"B  \"),",
     "        Ok(n) => matches!(&n[8..], b\"A  \" | b\"B  \"),",
     ["TST-M6-CONFIG-WRITE-SCOPE"], "SECURITY: any .A or .B in /SYSTEM is writable: step 46 creates /SYSTEM/AUTHD.A, probe=0x2e, created=1, then |ktest|fail| (forbidden)"),
    ("M164", "kernel/src/fs/vfs.rs",
     "        Ok(n) => n.starts_with(b\"CFG\") && matches!(&n[8..], b\"A  \" | b\"B  \"),",
     "        Ok(n) => n.starts_with(b\"CFG\"),",
     ["TST-M6-CONFIG-WRITE-SCOPE"], "SECURITY: any CFG* name in /SYSTEM is writable: step 47 creates /SYSTEM/CFGPRB.C, probe=0x2f, created=1, then |ktest|fail| (forbidden)"),
    # ---- M6 (WP-49): libui pointer hit-testing and the context menu (ui.md v1.6 §3.6); killer
    # TST-M6-UI-UNIT (user/libui/tests/pointer_menu.rs). SECURITY set: M168 (a disabled item is
    # how an application withholds an action, so choosing it must be impossible).
    ("M165", "user/libui/src/lib.rs",
     "    x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h",
     "    x >= r.x && x <= r.x + r.w && y >= r.y && y < r.y + r.h",
     ["TST-M6-UI-UNIT"], "the hit-test takes the column after an element's right edge as inside it: pointer_focuses_and_activates_the_element_under_it fails (a press at r.x + r.w focuses and activates the button), test result FAILED. 7 passed; 1 failed"),
    ("M166", "user/libui/src/lib.rs",
     "            .filter(|&i| self.elements[i].role.focusable())",
     "            .filter(|_| true)",
     ["TST-M6-UI-UNIT"], "a left press focuses a label: pointer_focuses_and_activates_the_element_under_it fails (Focus to the label instead of None), test result FAILED. 7 passed; 1 failed"),
    ("M167", "user/libui/src/lib.rs",
     "        self.focus = Some(owner);",
     "        let _ = owner;",
     ["TST-M6-UI-UNIT"], "Esc (and an outside press or a choice) closes the menu without returning the focus to its opener: focused() stays None; esc_and_outside_click_close_and_return_focus, context_menu_opens_by_three_ways and menu_wraps_skips_separators_and_disabled_never_chooses fail, test result FAILED. 5 passed; 3 failed"),
    ("M168", "user/libui/src/lib.rs",
     "        if it.separator || !it.enabled {",
     "        if it.separator {",
     ["TST-M6-UI-UNIT"], "SECURITY: Enter on a disabled menu item emits Choose: menu_wraps_skips_separators_and_disabled_never_chooses fails (Some(Choose(3, 3)) instead of None), test result FAILED. 7 passed; 1 failed"),
    ("M169", "user/libui/src/lib.rs",
     "            let opened = m.ax - w;",
     "            let opened = m.ax;",
     ["TST-M6-UI-UNIT"], "in RTL the menu is anchored by its left edge and opens rightwards: menu_mirrors_in_rtl fails (the right edge is not the element's start edge), test result FAILED. 7 passed; 1 failed"),
    # ---- M6 (WP-80): the confirm dialog (ui.md v1.7 §3.7); killer TST-M6-UI-CONFIRM
    # (user/libui/tests/confirm.rs). SECURITY: M171 (a cancel becomes consent).
    ("M171", "user/libui/src/lib.rs",
     "            KEY_ESC => self.give(Answer::Cancel, Event::Cancel),",
     "            KEY_ESC => self.give(Answer::Yes, Event::Cancel),",
     ["TST-M6-UI-CONFIRM"], "SECURITY: Esc answers Yes, so a cancel becomes consent: confirm_default_esc_enter (answer() Some(Yes) instead of Some(Cancel)) and confirm_narrator_lines (\"answer yes\" instead of \"answer cancel\") fail, test result: FAILED. 3 passed; 2 failed"),
    # ---- M6 (WP-50, 50a): the list view (ui.md v1.8 §3.8); killer TST-M6-LISTVIEW-UNIT
    # (user/libui/tests/listview.rs). SECURITY: M176 (a range selects rows the user did not see
    # chosen), M177 (typing opens a row), M179 (a denied folder reported empty), M180 (a name
    # reorders its own extension).
    ("M176", "user/libui/src/list.rs",
     "                self.set_sel(src.order(p), true);",
     "                self.set_sel(p, true);",
     ["TST-M6-LISTVIEW-UNIT"], "SECURITY: a Shift range selects display positions taken as row ids, so in any order but the identity an action on the selection reaches rows the user did not select: single_and_multi_selection ([1, 2] instead of [17, 18] in the reversed order) and sort_stable_and_selection_follows_identity fail, test result: FAILED. 9 passed; 2 failed"),
    ("M177", "user/libui/src/list.rs",
     "                return self.move_to(src, pos, 0);",
     "                return ListEvent::Activate(src.order(pos));",
     ["TST-M6-LISTVIEW-UNIT"], "SECURITY: a type-ahead match activates the row, so typing opens a file: typeahead_latin_and_arabic (Activate(1) instead of Focus(1)) and focus_stays_visible fail, test result: FAILED. 9 passed; 2 failed"),
    ("M178", "user/libui/src/list.rs",
     "            KEY_END => Some(last),",
     "            KEY_END => Some(self.n),",
     ["TST-M6-LISTVIEW-UNIT"], "End goes one past the last row and the view asks the application for position n: visible_rows_bounded_0_1_10000, home_end_pgup_pgdn_exact, single_and_multi_selection, row_narrator_lines_en_ar and focus_stays_visible fail (the RowSource panics on position n), test result: FAILED. 6 passed; 5 failed"),
    ("M179", "user/libui/src/list.rs",
     "        if let Some(r) = self.denied {",
     "        if let Some(r) = self.denied.filter(|_| false) {",
     ["TST-M6-LISTVIEW-UNIT"], "SECURITY (false report): a denied list is described state=empty, so a folder the user may not read is announced as having nothing in it: empty_and_denied_states_text fails, test result: FAILED. 10 passed; 1 failed"),
    ("M180", "user/libui/src/list.rs",
     "        out[n] = if is_bidi_control(c) || is_control(c) {",
     "        out[n] = if is_control(c) {",
     ["TST-M6-LISTVIEW-UNIT"], "SECURITY: a bidi override in a cell is drawn and obeyed, so photo<U+202E>gpj.exe shows as an image name: bidi_controls_in_cells_shown_not_obeyed fails (out[5] is 0x202E, not U+FFFD), test result: FAILED. 10 passed; 1 failed"),
    ("M181", "user/libui/src/list.rs",
     "        let total = self.n;",
     "        let total = self.visible().1;",
     ["TST-M6-LISTVIEW-UNIT"], "row k/n counts the visible rows, not all of them: row_narrator_lines_en_ar fails (row 500/10 instead of row 500/500), test result: FAILED. 10 passed; 1 failed"),
    # ---- M6 (WP-94): a described value cannot forge its line (ui.md v1.9 §3.9, RSK-022).
    ("M193", "user/libui/src/lib.rs",
     "        let named = c == '\"' || list::is_control(cp) || list::is_bidi_control(cp);",
     "        let named = false;",
     ["TST-M5-UI-UNIT"], "SECURITY: a value is written between the quotes as it is: a quote forges an attribute and a newline a second narrator line; a_quote_in_a_typed_value_cannot_forge_an_attribute, a_set_value_with_a_newline_stays_one_line, separators_and_bidi_controls_in_a_value_are_named_not_obeyed and a_long_escaped_value_is_cut_at_a_whole_character_and_still_closed fail, test result: FAILED. 15 passed; 4 failed"),
    # ---- M6 (WP-82): the interactive LOAD budget (boot.md v1.1, «مهلة LOAD»); killer TST-M0-003's
    # source guard (tests/test_ci_workflows.py LoadBudget). M174 (the received-transcript check in
    # tools/project.py) is not registrable: the harness restores only kernel/ and user/ and drives
    # its killers through tools/project.py itself; TST-M5-LAB-TOOL's cases are that check's guard.
    ("M175", "kernel/src/kmain.rs",
     "pub const LOAD_BUDGET_TICKS: u64 = 10_000;",
     "pub const LOAD_BUDGET_TICKS: u64 = 2_000;",
     ["TST-M0-003"], "the LOAD budget back to 2000 ticks (under the 1096 measured on CI run 42696067096): test_the_interactive_load_wait_uses_the_named_budget fails (kernel/src/kmain.rs: LOAD_BUDGET_TICKS = 2_000, not 10000), TST-M0-003 FAILED"),
    # ---- M6 (WP-84): the interactive halt (boot.md v1.2); killer TST-M6-BOOT-HALT (NAWAH.EFI).
    # SECURITY: M172 (a failed manager boots on silently: no halt line, no band, no stop), M173
    # (a manager that never answered is reported as one that answered an error: the halt code
    # blames the manifest for a hang).
    ("M172", "kernel/src/kmain.rs",
     "        if !load.ok {",
     "        if load.ok && !load.ok {",
     ["TST-M6-BOOT-HALT"], "SECURITY: the interactive boot goes on after a failed manager: no halt line and no band, the kernel waits for ever; TST-M6-BOOT-HALT FAIL: phase 1 times out without OSX|<id>|kernel|halt|reason=svcmgr|code=4|wait_ticks= (timeout (hang))"),
    ("M173", "kernel/src/services.rs",
     '        (true, "K_E_SVC_TIMEOUT") => 2,',
     '        (true, "K_E_SVC_TIMEOUT") => 4,',
     ["TST-M6-BOOT-HALT"], "SECURITY: a manager that never answered is halted with code 4 (an answered error) instead of 2: TST-M6-BOOT-HALT FAIL: phase 2 misses OSX|<id>|kernel|halt|reason=svcmgr|code=2|wait_ticks= and its screendump's digit cell is 000080, not 008000"),
    # ---- M6 (WP-99, RSK-024): a wait's deadline is kept whatever spins beside it (boot.md v1.3,
    # ADR-0010's 2026-11-14 amendment). M194 (SECURITY): the waiter stays at the lowest priority
    # after its deadline, so a manager that spins keeps the boot from its LOAD deadline and no
    # halt line appears. M195: a wait with a deadline competes at the best priority from its
    # start, so it starves what it waits for (ADR-0010's demotion is gone for it; join and
    # wait_process, which have no deadline, are untouched, so the boot still reaches the case).
    # M196: the boost outlives the wait (the waiter stays marked waiting with a deadline that
    # has passed). M197: an expired wait competes at the thread's own priority, not the best,
    # so a spinner of better priority still starves it.
    ("M194", "kernel/src/sched/mod.rs",
     "    } else if now >= t.wait_deadline {",
     "    } else if now >= t.wait_deadline && now < t.wait_deadline {",
     ["TST-M6-WAIT-DEADLINE", "TST-M6-BOOT-HALT"], "SECURITY: an expired wait keeps the lowest priority: TST-M6-WAIT-DEADLINE FAIL (exit 37: spinner_prio=0|ok=0 with late about 350 of a limit of 20) and TST-M6-BOOT-HALT FAIL: phase 3 (a spinning manager) times out with no svcmgr line and no halt line"),
    ("M195", "kernel/src/sched/mod.rs",
     "    } else if now >= t.wait_deadline {",
     "    } else if now >= t.wait_deadline || t.wait_deadline != u64::MAX {",
     ["TST-M6-WAIT-DEADLINE"], "a wait with a deadline competes at the best priority before it: beside the priority-1 spinner the waiter is run before its deadline (more than the three polls allowed, or the spinner never runs), spinner_prio=1|ok=0, exit 37, TST-M6-WAIT-DEADLINE FAIL"),
    ("M196", "kernel/src/sched/mod.rs",
     "    set_waiting(false, u64::MAX);\n    held",
     "    held",
     ["TST-M6-WAIT-DEADLINE"], "the boost is never taken back after poll_until: beside the priority-0 spinner the case's thread keeps running after its wait (resumed before the spinner gave up, under spin_ticks=400), spinner_prio=0|ok=0, exit 37, TST-M6-WAIT-DEADLINE FAIL"),
    ("M197", "kernel/src/sched/mod.rs",
     "    } else if now >= t.wait_deadline {\n        0\n",
     "    } else if now >= t.wait_deadline {\n        t.priority\n",
     ["TST-M6-WAIT-DEADLINE"], "an expired wait competes at the thread's own priority: beside the priority-0 spinner the waiter comes back only when the spinner gives up (late past the limit of 20), spinner_prio=0|ok=0, exit 37, TST-M6-WAIT-DEADLINE FAIL"),
    # ---- M6 (WP-100): the application registry's entry parser (apps.md v1 §3, ADR-0023 item 6).
    # M198 (SECURITY): the reserved-id check removed, so an entry may take the id `session`,
    # `desktop`, `narrator` or a service's name and be shown and spoken as one.
    ("M198", "user/nawah-apps/src/lib.rs",
     "    if RESERVED.contains(&id) {",
     "    if RESERVED.contains(&id) && false {",
     ["TST-M6-APP-REGISTRY-FUZZ"], "SECURITY: a reserved id is accepted as an application id: every_service_of_the_system_manifest_is_a_reserved_id, malformed_entries_are_refused_by_name, seeded_generated_malformed_entries_are_refused_by_name, the_contracts_lists_equal_the_crates_and_the_models and the_registry_refuses_duplicates_overflow_and_wrong_file_names fail, test result: FAILED. 4 passed; 5 failed"),
    # ---- M6 (WP-97): a window title in the compositor's own narrator lines (display.md v1.14).
    # M199 (SECURITY): the naming removed, so a title's quote closes it and adds attributes to
    # the compositor's line, and its controls and bidi controls pass as they are.
    ("M199", "user/apps/displayd/src/main.rs",
     "            let named = cp == 0x22 || is_control(cp) || is_bidi_control(cp);",
     "            let named = false && (cp == 0x22 || is_control(cp) || is_bidi_control(cp));",
     ["TST-M5-WINDOW-TITLE"], "SECURITY: a window title is written between the quotes as it is: the narrator reads `window \"x\" focused role=\"button\" focused` (a forbidden marker) and the transcript differs from platform/pc-qemu/expect/window-title.txt at its first line, TST-M5-WINDOW-TITLE FAIL"),
    # M200 (SECURITY): the resize line (say_size) writes the title as it is, while the focus
    # line still names it.
    ("M200", "user/apps/displayd/src/main.rs",
     "            let cut = put_title(&mut o, shown).saturating_add(w.title_cut);",
     "            let cut = {\n                o.put(shown);\n                w.title_cut\n            };",
     ["TST-M5-WINDOW-TITLE-RESIZE"], "SECURITY: the resize line writes the title between the quotes as it is: the narrator reads `window \"x\" resized 9x9 role=\"button\" resized 48x32` (a forbidden marker), the required named resize line is missing and the transcript differs at its second line, TST-M5-WINDOW-TITLE-RESIZE FAIL"),
    # M201, M202 (SECURITY, WP-104, ADR-0013 decision 9): the disk after a timed-out request.
    # M201: the timeout branch no longer stops the device, so the next requests are submitted on
    # the shared header, status byte, buffer and descriptors while the old one may still complete.
    ("M201", "kernel/src/drivers/virtio_blk.rs",
     "            if spins > limit {\n                DISK_STOPPED.store(true, Ordering::SeqCst);\n                self.stopped = true;\n                return Err(BlkError::Timeout);",
     "            if spins > limit {\n                DISK_STOPPED.store(true, Ordering::SeqCst);\n                return Err(BlkError::Timeout);",
     ["TST-M3-BLK-TIMEOUT"], "SECURITY: after a timed-out request the disk serves the next read, write and flush: the line carries after_read=ok, after_write=ok and after_flush=ok (forbidden markers), TST-M3-BLK-TIMEOUT FAIL"),
    # M202: a stopped device refuses a write only after copying its bytes into the shared buffer
    # (the buffer a pending request's device side may still read or write).
    ("M202", "kernel/src/drivers/virtio_blk.rs",
     "        self.refuse_stopped()?;\n        self.check_range(sector, buf.len())?;\n        dma::bytes_mut(self.data, buf.len()).copy_from_slice(buf);\n        self.request(T_OUT, sector, buf.len(), false)",
     "        self.check_range(sector, buf.len())?;\n        dma::bytes_mut(self.data, buf.len()).copy_from_slice(buf);\n        self.refuse_stopped()?;\n        self.request(T_OUT, sector, buf.len(), false)",
     ["TST-M3-BLK-TIMEOUT"], "SECURITY: a refused write has already changed the shared buffer: the line reads buffer_kept=0 (a forbidden marker), TST-M3-BLK-TIMEOUT FAIL"),
    # M203: a read whose request failed hands the shared buffer (an earlier request's bytes) to
    # its caller before it answers the error.
    ("M203", "kernel/src/drivers/virtio_blk.rs",
     "        self.request(T_IN, sector, buf.len(), true)?;\n        buf.copy_from_slice(dma::bytes_mut(self.data, buf.len()));\n        Ok(())",
     "        let r = self.request(T_IN, sector, buf.len(), true);\n        buf.copy_from_slice(dma::bytes_mut(self.data, buf.len()));\n        r",
     ["TST-M3-BLK-TIMEOUT"], "SECURITY: the read that timed out copies the shared buffer over its caller's guard bytes: the line carries caller_kept=0 (a forbidden marker), TST-M3-BLK-TIMEOUT FAIL"),
    # M204: a stopped device publishes a flush to the device and refuses it only afterwards.
    ("M204", "kernel/src/drivers/virtio_blk.rs",
     "        self.refuse_stopped()?;\n        if !self.info.flush {\n            return Ok(());\n        }\n        self.request(T_FLUSH, 0, 0, false)",
     "        if !self.info.flush {\n            return Ok(());\n        }\n        let r = self.request(T_FLUSH, 0, 0, false);\n        self.refuse_stopped()?;\n        r",
     ["TST-M3-BLK-TIMEOUT"], "SECURITY: a refused flush has been published to the device: the answer is still K_E_BLK_NEEDS_RESET but the line no longer carries published=0 (the required line is missing), TST-M3-BLK-TIMEOUT FAIL"),
    # M205-M207 (SECURITY, WP-105, files.md v1.5, ADR-0014 item 6): delete and truncate keep the
    # directory entry ahead of the frees. M205: delete frees the chain before it writes the entry.
    ("M205", "kernel/src/fs/fat32.rs",
     "        let mut dead = e;\n        dead.name[0] = 0xE5;\n        self.store_entry(&dead)?;\n        let freed = if e.first >= 2 {\n            self.free_chain(e.first)?\n        } else {\n            0\n        };\n        Ok(freed)",
     "        let freed = if e.first >= 2 {\n            self.free_chain(e.first)?\n        } else {\n            0\n        };\n        let mut dead = e;\n        dead.name[0] = 0xE5;\n        self.store_entry(&dead)?;\n        Ok(freed)",
     ["TST-M3-FAT32-FAULT-UNLINK"], "SECURITY: a delete that fails after a cluster is freed in the FAT copy the kernel reads leaves the name with a chain that runs into free clusters: the sweep's line carries a bad count that is not 0, TST-M3-FAT32-FAULT-UNLINK FAIL"),
    # M206: truncate frees the chain before the emptied entry is stored.
    ("M206", "kernel/src/fs/fat32.rs",
     "        self.store_entry(&emptied)?;\n        *file = emptied;\n        if old_first >= 2 {\n            self.free_chain(old_first)\n        } else {\n            Ok(0)\n        }",
     "        let freed = if old_first >= 2 {\n            self.free_chain(old_first)?\n        } else {\n            0\n        };\n        self.store_entry(&emptied)?;\n        *file = emptied;\n        Ok(freed)",
     ["TST-M3-FAT32-FAULT-TRUNCATE"], "SECURITY: a truncation that fails after a cluster is freed in the FAT copy the kernel reads leaves the stored entry pointing at freed clusters: the sweep's line carries a bad count that is not 0, TST-M3-FAT32-FAULT-TRUNCATE FAIL"),
    # M207: truncate empties the shared node before the emptied entry is stored.
    ("M207", "kernel/src/fs/fat32.rs",
     "        self.store_entry(&emptied)?;\n        *file = emptied;\n",
     "        *file = emptied;\n        self.store_entry(&emptied)?;\n",
     ["TST-M3-FAT32-FAULT-TRUNCATE"], "SECURITY: a truncation whose entry write is refused leaves the node of every open empty over a file the disk still holds whole: the sweep's line carries node_differs that is not 0, TST-M3-FAT32-FAULT-TRUNCATE FAIL"),
    # ---- M6 tooling mutants (WP-90 harness item: reset() restores tools/, tests/ and .github/;
    # host killers only, no image). M174 (WP-82): the received-transcript check of forbidden
    # markers removed. M185-M190 (WP-83, 83a): adopt-native and the verify workflow's merge job.
    # All SECURITY: each reopens a path for a forged, foreign or partial verdict to become evidence.
    ("M174", "tools/project.py",
     '    present_forbidden += [f"{m} ({name})" for name, r in received for m in forbidden if m in r]',
     "    present_forbidden += []",
     ["TST-M5-LAB-TOOL"], "SECURITY: a forbidden marker the guest wrote only to the console transcript no longer fails the case"),
    ("M185", "tools/project.py",
     "            if want != got:\n                print(f\"adopt refused: {d.name} names {got!r} where {name} is {want!r}\")",
     "            if want != got and name != \"GITHUB_RUN_ATTEMPT\":\n                print(f\"adopt refused: {d.name} names {got!r} where {name} is {want!r}\")",
     ["TST-M0-007"], "SECURITY: adopt-native no longer compares the run attempt, so another attempt's directories are adopted as this run's"),
    ("M186", "tools/project.py",
     "        have = run_ci_identity(d)\n        if have is None:\n            print(f\"adopt refused: {d.name} carries no ci identity",
     "        have = run_ci_identity(d) or tuple(expect)\n        if have is None:\n            print(f\"adopt refused: {d.name} carries no ci identity",
     ["TST-M0-007"], "SECURITY: a new directory without ci identity is adopted as if this run wrote it"),
    ("M187", ".github/workflows/verify.yml",
     "        if: ${{ !cancelled() && steps.adopt.outcome == 'success' }}",
     "        if: always()",
     ["TST-M0-003"], "SECURITY: Publish runs even when the adopt step failed or the run was cancelled"),
    ("M188", ".github/workflows/verify.yml",
     "  contents: read  # the code under test runs here",
     "  contents: write  # the code under test runs here",
     ["TST-M0-003"], "SECURITY: the top-level token may write, so the code under test in job a can push"),
    ("M189", ".github/workflows/verify.yml",
     "    needs: [a, b, shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11, shard-12, g]\n    if: ${{ !cancelled() }}",
     "    needs: [a, b, shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11, shard-12, g]\n    if: always()",
     ["TST-M0-003"], "SECURITY: the merge job runs on a cancelled run (always() instead of !cancelled())"),
    ("M190", ".github/workflows/verify.yml",
     'echo "::error title=Merge::evidence-$slot is missing or holds no run directory"; exit 1',
     'echo "::error title=Merge::evidence-$slot is missing or holds no run directory"; continue',
     ["TST-M0-003"], "SECURITY: the missing-slot tolerance restored: a missing or empty slot is skipped and the rest adopted"),
    # M220..M224 (SECURITY, WP-117, files.md v1.9, ADR-0014 item 10): the file system stops with
    # the disk. M220: fs::with no longer asks whether the disk has stopped.
    ("M220", "kernel/src/fs/mod.rs",
     "    let g = VOLUME.lock();\n    if stopped() {\n        return Err(stop_error());\n    }\n",
     "    let g = VOLUME.lock();\n",
     ["TST-M3-FAT32-STOP"], "SECURITY: after the disk has stopped a read at the end of an open file, a write of no bytes and a stat of the root answer success from memory, to a process too: the kernel's own calls carry end_read=ok, empty_write=ok, root_stat=ok and stale_write=K_E_FS_RANGE (the process is still answered ERR_IO by the system-call layer), TST-M3-FAT32-STOP FAIL"),
    # M221: vfs::seek no longer asks.
    ("M221", "kernel/src/fs/vfs.rs",
     "    if super::stopped() {\n        return Err(super::stop_error());\n    }\n    if pos > u64::from(f.node.lock().size) {",
     "    if pos > u64::from(f.node.lock().size) {",
     ["TST-M3-FAT32-STOP"], "SECURITY: after the disk has stopped a seek answers success from memory and moves the position: the kernel's own seek carries seek=ok and pos_moved=1 (the process is still answered ERR_IO by the system-call layer), TST-M3-FAT32-STOP FAIL"),
    # M222: vfs::write refuses a position past the size from the node, before the disk is asked.
    ("M222", "kernel/src/fs/vfs.rs",
     "        super::with(|fs| fs.write(&mut e, pos as u32, data))?\n",
     "        if pos > u64::from(e.size) {\n            return Err(FsError::Range);\n        }\n        super::with(|fs| fs.write(&mut e, pos as u32, data))?\n",
     ["TST-M3-FAT32-STOP"], "SECURITY: after the disk has stopped a write through an open whose position is past the size answers the range error from memory: the line carries stale_write=K_E_FS_RANGE, TST-M3-FAT32-STOP FAIL"),
    # M223: vfs::seek asks only after it has moved the position.
    ("M223", "kernel/src/fs/vfs.rs",
     "    if super::stopped() {\n        return Err(super::stop_error());\n    }\n    if pos > u64::from(f.node.lock().size) {\n        return Err(FsError::Range);\n    }\n    f.pos = pos;\n    Ok(pos)",
     "    if pos > u64::from(f.node.lock().size) {\n        return Err(FsError::Range);\n    }\n    f.pos = pos;\n    if super::stopped() {\n        return Err(super::stop_error());\n    }\n    Ok(pos)",
     ["TST-M3-FAT32-STOP"], "SECURITY: a seek refused after the disk has stopped has already moved the open's position: the line carries pos_moved=1, TST-M3-FAT32-STOP FAIL"),
    # M224: the driver stops the device and does not set the flag the file system reads.
    ("M224", "kernel/src/drivers/virtio_blk.rs",
     "                DISK_STOPPED.store(true, Ordering::SeqCst);\n                self.stopped = true;\n",
     "                self.stopped = true;\n",
     ["TST-M3-FAT32-STOP"], "SECURITY: the disk stops and the file system never learns it: the calls that ask nothing of the disk answer from memory and no line kernel|fs|stopped is written, TST-M3-FAT32-STOP FAIL"),
    # M226..M238 (SECURITY, WP-126): the host image check names a damaged entry and a reserved
    # value in any FAT copy. M226: an entry's first cluster is no longer looked at.
    ("M226", "tools/fat32.py",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     "                if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check` walks a directory or a file whose first cluster is no cluster of the volume as an empty one and names nothing: the host cases on the damaged directory and the damaged file fail, TST-M3-FAT32-TOOL FAIL"),
    # M227: a first cluster of 0 is accepted for a directory as it is for an empty file.
    ("M227", "tools/fat32.py",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     "                if not 2 <= entry_first < img.clusters + 2 and entry_first != 0:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a directory entry whose first cluster is 0 is walked as an empty directory: the host case on the directory with a first cluster of 0 fails, TST-M3-FAT32-TOOL FAIL"),
    # M231: the empty file is no longer excepted.
    ("M231", "tools/fat32.py",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     "                if not 2 <= entry_first < img.clusters + 2:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: every empty file is called damaged, so every image a guest case leaves with one fails for no fault: the host case on the healthy empty file fails, TST-M3-FAT32-TOOL FAIL"),
    # M232: a first cluster past the volume, or an end mark, is accepted.
    ("M232", "tools/fat32.py",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     "                if not 2 <= entry_first and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a directory or an empty file whose first cluster is an end mark is walked as empty and named nowhere: the host cases with a first cluster of 0x0FFFFFF8 fail, TST-M3-FAT32-TOOL FAIL"),
    # M236: only attributes that are exactly a directory's make an entry a directory.
    ("M236", "tools/fat32.py",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):\n",
     "                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] == ATTR_DIR):\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a directory whose attributes carry another bit besides the directory's (the kernel asks that bit alone) passes with a first cluster of 0: the host case with attributes 0x30 fails, TST-M3-FAT32-TOOL FAIL"),
    # M238: the first number past the volume is followed as a cluster.
    ("M238", "tools/fat32.py",
     "            if c >= img.clusters + 2 or c in seen:\n",
     "            if c > img.clusters + 2 or c in seen:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a link to the first number that is no cluster of the volume is followed and the file is not named: the host case with that number in a chain fails, TST-M3-FAT32-TOOL FAIL"),
    # M228: a chain that reaches the reserved value 1 ends quietly.
    ("M228", "tools/fat32.py",
     "        if c == 1 and got:\n",
     "        if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: the reserved value 1 in a chain of either FAT copy is taken for the chain's end: the host cases on the second copy and on the first fail, TST-M3-FAT32-TOOL FAIL"),
    # M229: the scan for reserved and out-of-range values reads the first copy only.
    ("M229", "tools/fat32.py",
     "    for fat in range(1, img.nfats):\n        for c in range(2, img.clusters + 2):\n",
     "    for fat in range(1, 1):\n        for c in range(2, img.clusters + 2):\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a reserved or out-of-range value outside every chain in the second FAT copy is no problem: the host case fails, TST-M3-FAT32-TOOL FAIL"),
    # M234: the second copy is scanned only with --faulted.
    ("M234", "tools/fat32.py",
     "    for fat in range(1, img.nfats):\n        for c in range(2, img.clusters + 2):\n",
     "    for fat in range(1, img.nfats if faulted else 1):\n        for c in range(2, img.clusters + 2):\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: without --faulted an invalid value in the second copy is reported only as copies that differ, not by its entry: the host case's plain-mode half fails, TST-M3-FAT32-TOOL FAIL"),
    # M235: the first number past the volume passes the second copy's scan.
    ("M235", "tools/fat32.py",
     "            if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):\n                problems.append(f\"FAT{fat}[{c}] = {v:#x} invalid\"); break\n",
     "            if v == 1 or (2 <= v < 0x0FFFFFF7 and v > img.clusters + 2):\n                problems.append(f\"FAT{fat}[{c}] = {v:#x} invalid\"); break\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: the first number that is no cluster of the volume is accepted in the second FAT copy: the host case fails, TST-M3-FAT32-TOOL FAIL"),
    # M237: the second copy's scan no longer knows the reserved values below the bad-cluster mark.
    ("M237", "tools/fat32.py",
     "            if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):\n                problems.append(f\"FAT{fat}[{c}] = {v:#x} invalid\"); break\n",
     "            if v == 1 or (2 <= v < 0x0FFFFFF1 and v >= img.clusters + 2):\n                problems.append(f\"FAT{fat}[{c}] = {v:#x} invalid\"); break\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: the reserved values 0x0FFFFFF1 to 0x0FFFFFF6 outside every chain pass the second FAT copy's scan: the host case with 0x0FFFFFF6 fails, TST-M3-FAT32-TOOL FAIL"),
    # M230: the first copy is no longer scanned for reserved and out-of-range values.
    ("M230", "tools/fat32.py",
     "        if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):\n            problems.append(f\"FAT[{c}] = {v:#x} invalid\"); break\n",
     "        if False:\n            problems.append(f\"FAT[{c}] = {v:#x} invalid\"); break\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a reserved or out-of-range value outside every chain in the first FAT copy is counted as a lost cluster and can meet a case's exact count (the red team ran it: exit 0 with --expect-lost 2): the host case on the first copy fails, TST-M3-FAT32-TOOL FAIL"),
    # M233: the other FAT copies are walked only with --faulted.
    ("M233", "tools/fat32.py",
     "    for fat in range(1, img.nfats):\n        strict_o, longer_o, owned_o, complete_o, reached_o = tree_findings(img, fat)\n",
     "    for fat in range(1, img.nfats if faulted else 1):\n        strict_o, longer_o, owned_o, complete_o, reached_o = tree_findings(img, fat)\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: without --faulted a reserved or out-of-range value in a chain of the second copy is not tied to the file or the directory that holds it: the plain-mode halves of the host cases fail, TST-M3-FAT32-TOOL FAIL"),
    # M225: the system-call layer no longer asks first for the calls of the files contract.
    ("M225", "kernel/src/syscall/mod.rs",
     "    if crate::fs::stopped() {\n        ERR_IO\n    } else {\n        f()\n    }\n",
     "    f()\n",
     ["TST-M3-FAT32-STOP"], "SECURITY: after the disk has stopped a file call whose path, flags or handle a working disk would refuse answers that refusal, not ERR_IO: the application exits at its step 13, the line carries app_exit=0xd, TST-M3-FAT32-STOP FAIL"),
    # M219 (SECURITY, WP-120, files.md v1.8, ADR-0014 item 9): the first FAT copy, the one the
    # kernel reads, is written first again.
    ("M219", "kernel/src/fs/fat32.rs",
     "        for k in (0..self.fats).rev() {\n            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;",
     "        for k in 0..self.fats {\n            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;",
     ["TST-M3-FAT32-FAULT-WRITE", "TST-M3-FAT32-FAULT-UNLINK", "TST-M3-FAT32-FAULT-TRUNCATE", "TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-CREATE-COPIES"], "SECURITY: a link written in the first FAT copy and refused in the second stays missing there once the append is made again: the host check finds a chain shorter than its size in the second copy and other numbers of lost clusters and longer chains than the case pins (56 and 3 where 53 and 2 are), TST-M3-FAT32-FAULT-WRITE FAIL; the delete and the truncate cases count 9 lost where 12 are pinned, FAIL; in the create sweep, which reads both copies after every call since WP-138, the second copy is behind the first (the directory's chain shorter along it: second_shorter=2; a cluster marked in the first copy and free in the second: first_marks=7; second_names=1, beside grown=2 and retry_grew=6), TST-M3-FAT32-FAULT-CREATE FAIL (seen locally: TST-M3-FAT32-FAULT-ONE-CREATE fails too, by the same fields); TST-M3-FAT32-FAULT-CREATE-COPIES FAIL (second_shorter=2, first_marks=7, second_links=2, second_names=1, second_longer=0, second_marks=0)"),
    # M252..M254 (SECURITY, WP-124, files.md v1.10, ADR-0014 item 11): a FAT write stops at its
    # first refused write. The older fault cases refuse write N and every write after it, so a
    # refusal that fat_set swallows is followed by another refused, checked write and nothing
    # shows; the two cases under the hook's once mode refuse write N alone.
    # M252: a refused FAT write is ignored.
    ("M252", "kernel/src/fs/fat32.rs",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            block::write(sector, &s)?;\n",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            let _ = block::write(sector, &s);\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: a delete or a truncation whose FAT write the disk refused goes on and answers success, the two FAT copies no longer agreeing on a cluster the kernel may hand out again: the sweeps' lines carry failed, io and stopped below 9 and once_refused=0, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M253: only the write of the copy the kernel reads is checked.
    ("M253", "kernel/src/fs/fat32.rs",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            block::write(sector, &s)?;\n",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            let r = block::write(sector, &s);\n            if k == 0 {\n                r?;\n            }\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: a refused write of the second FAT copy is swallowed and the call goes on: WP-120's defect comes back (the copies part and no error says so): the sweeps' lines carry failed, io and stopped below 9 and once_refused=0, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M254: the test kernel's once mode refuses every later write too (it is the older mode).
    ("M254", "kernel/src/block/mod.rs",
     "        n >= FAIL_FROM.load(Ordering::SeqCst) && n <= FAIL_TO.load(Ordering::SeqCst)\n",
     "        n >= FAIL_FROM.load(Ordering::SeqCst)\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: the hook that should refuse one write alone refuses all after it, so the two cases would judge what the older cases judge and let M252 and M253 live: the sweeps' lines carry once_next_ok=0, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M255..M257 (SECURITY, WP-124, from its red team): the whole call stops at the refused
    # write, not fat_set alone. M255: after the main FSInfo write is refused the backup is
    # written and the first error returned at the end; only the count of the writes shows it.
    ("M255", "kernel/src/fs/fat32.rs",
     "            s[492..496].copy_from_slice(&hint.to_le_bytes());\n            block::write(sector, &s)?;\n",
     "            s[492..496].copy_from_slice(&hint.to_le_bytes());\n            let r = block::write(sector, &s);\n            if r.is_err() {\n                if sector == u64::from(self.fsinfo) && self.bk_boot != 0 {\n                    let _ = block::write(u64::from(self.bk_boot) + 1, &s);\n                }\n                r?;\n            }\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: a call whose write the disk refused goes on writing and reports the error at its end: the answer and the image are the ones of a call that stopped, and only the count of its disk writes differs: the sweeps' lines carry stopped=8 beside failed=9 and io=9, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M256: the refusal of the main FSInfo write is swallowed.
    ("M256", "kernel/src/fs/fat32.rs",
     "            s[492..496].copy_from_slice(&hint.to_le_bytes());\n            block::write(sector, &s)?;\n",
     "            s[492..496].copy_from_slice(&hint.to_le_bytes());\n            let r = block::write(sector, &s);\n            if sector != u64::from(self.fsinfo) {\n                r?;\n            }\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: a delete or a truncation whose main FSInfo write the disk refused answers success (files.md v1.10 says it answers an I/O error until WP-123 decides otherwise with a case): the sweeps' lines carry failed=8, io=8 and stopped=8, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M257: a refused FAT write is tried once more.
    ("M257", "kernel/src/fs/fat32.rs",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            block::write(sector, &s)?;\n",
     "            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());\n            if block::write(sector, &s).is_err() {\n                block::write(sector, &s)?;\n            }\n",
     ["TST-M3-FAT32-FAULT-ONE-UNLINK", "TST-M3-FAT32-FAULT-ONE-TRUNCATE"], "SECURITY: a FAT write the disk refused is sent again and the call answers success, so the caller never learns the disk refused a write (files.md v1.10: the call stops and answers an I/O error): the sweeps' lines carry failed=3, io=3, stopped=3 and once_refused=0, TST-M3-FAT32-FAULT-ONE-UNLINK and TST-M3-FAT32-FAULT-ONE-TRUNCATE FAIL"),
    # M258..M260 (SECURITY, WP-131, files.md v1.11, ADR-0014 item 12): a write stops at its
    # first refused disk write. The older write case refuses write N and every write after it,
    # so a swallowed refusal is followed by another refused, checked write; the case under the
    # hook's once mode refuses write N alone. M258: the refusal of the write that zeroes a new
    # cluster is swallowed.
    ("M258", "kernel/src/fs/fat32.rs",
     "                        block::write(base + u64::from(i), &zero)?;\n",
     "                        let _ = block::write(base + u64::from(i), &zero);\n",
     ["TST-M3-FAT32-FAULT-ONE-WRITE", "TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE"], "SECURITY: a write whose new cluster the disk refused to zero goes on and answers success; the case sees that answer (on the lab's volume a cluster is one sector and the data write that follows covers it, so no unzeroed byte is left to read here; where a cluster is not covered, as in a directory that grows, it is read: the create case under one refused write): the sweeps' lines carry failed=20, bad=3 and ghost=3 for a new file and failed=8 for an append, TST-M3-FAT32-FAULT-ONE-WRITE FAIL; and a create that grows its directory under a disk that refuses write N and all after asks for one write more at the zeroing's refusal (stopped=7 beside failed=8), TST-M3-FAT32-FAULT-CREATE FAIL; and with one write refused alone that create answers success with its new cluster linked and never zeroed, and the directory lists the names the cluster held (strays=90, failed=7, absent=7), TST-M3-FAT32-FAULT-ONE-CREATE FAIL"),
    # M259: the refusal of a data write is swallowed.
    ("M259", "kernel/src/fs/fat32.rs",
     "            block::write(sector, &s)?;\n            done += n;\n",
     "            let _ = block::write(sector, &s);\n            done += n;\n",
     ["TST-M3-FAT32-FAULT-ONE-WRITE"], "SECURITY: a write whose data the disk refused answers success and the file reads bytes that were never stored: the sweeps' lines carry failed=20, bad=3 and ghost=3 for a new file and failed=8 for an append, TST-M3-FAT32-FAULT-ONE-WRITE FAIL"),
    # M260: after a refused data write one more disk write is asked for (the entry as it was)
    # before the error is returned.
    ("M260", "kernel/src/fs/fat32.rs",
     "            block::write(sector, &s)?;\n            done += n;\n",
     "            if let Err(e) = block::write(sector, &s) {\n                let _ = self.store_entry(file);\n                return Err(FsError::Io(e));\n            }\n            done += n;\n",
     ["TST-M3-FAT32-FAULT-ONE-WRITE"], "SECURITY: a write whose data write was refused asks for one more disk write (the entry as it was) and then reports the error: the answer and the image are those of a call that stopped, and only the count of its disk writes differs: the sweeps' lines carry stopped=20, 8 and 8 beside failed=23, 9 and 9, TST-M3-FAT32-FAULT-ONE-WRITE FAIL"),
    # M261..M263 (WP-133, files.md v1.12, ADR-0014 item 13): a create that must add a cluster to
    # its directory stops at its first refused disk write and leaves no name. No older sweep
    # runs a create (TST-M3-FAT32-STOP opens with O_CREATE after its disk stopped, once, with no
    # directory growing). M261 (SECURITY): the refusal of the write that links the
    # directory's tail to the new cluster is swallowed.
    ("M261", "kernel/src/fs/fat32.rs",
     "                self.fat_set(tail, n)?;\n",
     "                let _ = self.fat_set(tail, n);\n",
     ["TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE", "TST-M3-FAT32-FAULT-CREATE-COPIES"], "SECURITY: a create whose link of the directory's tail the disk refused goes on to the entry's write, into a cluster the directory does not reach; under a disk that refuses every later write too the answer and the image are those of a call that stopped and only the count of its disk writes differs: the line carries stopped=6 beside failed=8, TST-M3-FAT32-FAULT-CREATE FAIL; with one write refused alone the create answers success for a name no lookup finds (ghost=2, failed=6; after the refusal of the link's second write the name is listed along the second FAT copy alone: second_names=1), TST-M3-FAT32-FAULT-ONE-CREATE FAIL; TST-M3-FAT32-FAULT-CREATE-COPIES FAIL by second_names=1 alone"),
    # M262 (not SECURITY: no answer and no name along the first FAT copy differs): the new entry
    # is written into the new cluster before the directory's tail is linked to it.
    ("M262", "kernel/src/fs/fat32.rs",
     "                let n = self.alloc_cluster()?;\n                self.fat_set(tail, n)?;\n                EntryLoc {\n                    cluster: n,\n                    index: 0,\n                }\n            }\n        };\n",
     "                let n = self.alloc_cluster()?;\n                let loc = EntryLoc {\n                    cluster: n,\n                    index: 0,\n                };\n                let e = Entry {\n                    name,\n                    attr: ATTR_ARCHIVE,\n                    first: 0,\n                    size: 0,\n                    loc,\n                };\n                self.store_entry(&e)?;\n                self.fat_set(tail, n)?;\n                return Ok(e);\n            }\n        };\n",
     ["TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE", "TST-M3-FAT32-FAULT-CREATE-COPIES"], "the order of a growth's last writes is reversed: with the last write refused, the reversed order leaves a marked cluster that holds an entry and that the directory does not reach along the first FAT copy (lost once the create made again links another), where the present order leaves an empty cluster at the directory's end; no answer and no name along the first copy differs (the entry's name is then listed along the second FAT copy and not along the first until the next create: second_names=1 in both create cases, which read the second copy since WP-138); the line carries grown=0, retry_grew=8 and second_names=1 (the case's own judgement fails on the last) and the host counts six lost clusters where five are pinned, TST-M3-FAT32-FAULT-CREATE FAIL; TST-M3-FAT32-FAULT-ONE-CREATE FAIL by the same three fields; TST-M3-FAT32-FAULT-CREATE-COPIES, which once its sweep has started judges nothing but the second copy's fields, FAIL by second_names=1 alone"),
    # M263 (SECURITY): the refusal of the new entry's write is swallowed.
    ("M263", "kernel/src/fs/fat32.rs",
     "        self.store_entry(&e)?;\n        Ok(e)\n",
     "        let _ = self.store_entry(&e);\n        Ok(e)\n",
     ["TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE"], "SECURITY: a create whose entry the disk refused to store answers success, and the caller holds a file the volume does not name: the line carries failed=7 and io=7 (absent stays 8: the name is not on the disk), TST-M3-FAT32-FAULT-CREATE FAIL; under one refused write the same answer, counted as ghost=1, TST-M3-FAT32-FAULT-ONE-CREATE FAIL"),
    # M266 (SECURITY, from WP-134's red team): the hook's once mode refuses one write alone only
    # when that write is the next one; armed for a later write it refuses every write after it
    # too. The mode was shown for its first write only, and the once-mode sweeps read the same
    # numbers under both modes; the create case now makes each create again inside the armed
    # window.
    ("M266", "kernel/src/block/mod.rs",
     "        FAIL_TO.store(at, Ordering::SeqCst);\n",
     "        FAIL_TO.store(if nth == 1 { at } else { u32::MAX }, Ordering::SeqCst);\n",
     ["TST-M3-FAT32-FAULT-ONE-CREATE"], "SECURITY: the hook that should refuse write N alone refuses every write after it for N of two and more, so the once-mode cases would judge what the older cases judge: the create made again inside the armed window is refused and the line carries retry_ok=1, names=46 and dir_clusters=4, TST-M3-FAT32-FAULT-ONE-CREATE FAIL (seen locally: TST-M3-FAT32-FAULT-ONE-UNLINK, TST-M3-FAT32-FAULT-ONE-TRUNCATE and TST-M3-FAT32-FAULT-ONE-WRITE pass under it)"),
    # M267 (SECURITY, from WP-134's red team): the refusal of a new cluster's zeroing is answered
    # only after FSInfo's writes.
    ("M267", "kernel/src/fs/fat32.rs",
     "                    for i in 0..self.sectors_per_cluster {\n                        block::write(base + u64::from(i), &zero)?;\n                    }\n                    self.fsinfo_adjust(-1, k + 1)?;\n",
     "                    let mut r = Ok(());\n                    for i in 0..self.sectors_per_cluster {\n                        r = r.and(block::write(base + u64::from(i), &zero));\n                    }\n                    self.fsinfo_adjust(-1, k + 1)?;\n                    r?;\n",
     ["TST-M3-FAT32-FAULT-ONE-CREATE"], "SECURITY: an allocation whose zeroing the disk refused goes on to FSInfo's writes before it answers the error: the answer and everything the case reads are those of a call that stopped, and only the count of its disk writes differs (stopped=7 beside failed=8), TST-M3-FAT32-FAULT-ONE-CREATE FAIL (seen locally: TST-M3-FAT32-FAULT-CREATE fails too, by the same count)"),
    # M268 (SECURITY, from WP-138's red team; files.md v1.14, ADR-0014 item 15): the second FAT
    # copy's link of the directory's tail is written before the new cluster is zeroed. The create
    # made again writes that link over, so nothing the cases took before WP-138 sees it; the
    # second copy's fields, read before the create is made again, do.
    ("M268", "kernel/src/fs/fat32.rs",
     "                let n = self.alloc_cluster()?;\n                self.fat_set(tail, n)?;\n",
     "                let n = self\n                    .nth_free(1, self.alloc_end())?\n                    .ok_or(FsError::DiskFull)?;\n                self.fat_set(n, EOC)?;\n                let off = tail as usize * 4;\n                let mut s = [0u8; SECTOR];\n                for k in [1, 0] {\n                    let sector =\n                        u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;\n                    block::read(sector, &mut s)?;\n                    s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&n.to_le_bytes());\n                    block::write(sector, &s)?;\n                    if k == 1 {\n                        block::write(self.cluster_sector(n)?, &[0u8; SECTOR])?;\n                        self.fsinfo_adjust(-1, n + 1)?;\n                    }\n                }\n",
     ["TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE", "TST-M3-FAT32-FAULT-CREATE-COPIES"], "SECURITY: a growth that writes the second FAT copy's link of the directory's tail before it zeroes the new cluster: when the zeroing is refused, the second copy's chain of the directory is left on a cluster that still holds what a deleted file left, and a reader of that copy lists those entries as names; the create made again writes the link over, so the final image does not hold the link, and the host check and every number the create cases took before WP-138 are the present code's (by reading, the image differs only where nothing is pinned: FSInfo's free count, one decrement fewer, and one more lost cluster left unzeroed; seen locally: both cases as they were at fa8132331 pass with it); read before the create is made again, the line carries second_names=1 (the case's own judgement fails) and second_longer=4 where 1 is pinned, TST-M3-FAT32-FAULT-CREATE FAIL; TST-M3-FAT32-FAULT-ONE-CREATE FAIL by the same two fields; TST-M3-FAT32-FAULT-CREATE-COPIES, which once its sweep has started judges nothing but the second copy's fields, FAIL (second_names=1, second_longer=4, second_links=4)"),
    # M265 (SECURITY, WP-134, files.md v1.13, ADR-0014 item 14): a refusal that is answered only
    # after more disk writes. After the refused link of the directory's tail the create asks for
    # the writes that free the new cluster, then returns the error.
    ("M265", "kernel/src/fs/fat32.rs",
     "                self.fat_set(tail, n)?;\n",
     "                if let Err(e) = self.fat_set(tail, n) {\n                    let _ = self.fat_set(n, 0);\n                    return Err(e);\n                }\n",
     ["TST-M3-FAT32-FAULT-ONE-CREATE", "TST-M3-FAT32-FAULT-CREATE-COPIES"], "SECURITY: a create whose link the disk refused goes on writing before it answers the error (files.md v1.12: it asks for no disk write after the refused one): with one write refused alone the line carries stopped=6 beside failed=8 and the host counts 3 lost clusters where 5 are pinned, since the new cluster is freed again (when the refused write is the link's second, the second FAT copy is left with the directory's tail linked to a free cluster until the next create: second_free=1, read since WP-138), TST-M3-FAT32-FAULT-ONE-CREATE FAIL (seen locally: TST-M3-FAT32-FAULT-CREATE fails too, by stopped=6 alone); TST-M3-FAT32-FAULT-CREATE-COPIES, which once its sweep has started judges nothing but the second copy's fields, FAIL by second_free=1 and second_longer=0"),
    # M264 (SECURITY, from WP-133's red team): the zeroing of a new cluster lands on the sector
    # after it. The count of disk writes does not change, and on an image whose free clusters
    # are zeros the create case read every number it reads without the fault; it now dirties
    # the clusters its growths take.
    ("M264", "kernel/src/fs/fat32.rs",
     "                        block::write(base + u64::from(i), &zero)?;\n",
     "                        block::write(base + 1 + u64::from(i), &zero)?;\n",
     ["TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE"], "SECURITY: a new cluster is linked into a directory with the bytes it held before (the zeroing lands on the next sector, which on the lab's volume is the next cluster), and the directory lists names no create made: the line carries control=0 and retry_ok=7, TST-M3-FAT32-FAULT-CREATE FAIL, and TST-M3-FAT32-FAULT-ONE-CREATE FAIL with strays=195 beside them (seen locally when M3 had 48 cases: TST-M3-FAT32-FAULT-ONE-TRUNCATE fails too, by a message of fsck.fat on its image, and the other 46 pass)"),
    # M270..M272 (SECURITY, WP-106, RSK-027): the mount refuses a malformed boot sector with
    # K_E_FS_BAD_BPB, every bound in 64 bits (M269 is reserved for another item). M270: the data
    # region's start is summed in 32 bits again, wrapping.
    ("M270", "kernel/src/fs/fat32.rs",
     "        let data_start = u64::from(reserved) + u64::from(fats) * u64::from(fat_sectors);\n",
     "        let data_start = u64::from(reserved.wrapping_add(fats.wrapping_mul(fat_sectors)));\n",
     ["TST-M3-FAT32-BPB"], "SECURITY: a FAT size whose sum with the reserved sectors wraps 32 bits mounts with the data region over the first FAT (data start 64), over the reserved sectors (16) or over the boot sector (0): the lines carry sector=mul_wrap|clusters=131008|data_start=64, sector=add_wrap|clusters=131056|data_start=16 and sector=zero_start|clusters=131072|data_start=0, and the last refused=23|accepted=10|wrong=3, TST-M3-FAT32-BPB FAIL (seen locally on the case of 33 sectors)"),
    # M271: the check that the data region starts inside the volume is gone.
    ("M271", "kernel/src/fs/fat32.rs",
     "        if data_start >= total || total > capacity {\n",
     "        if total > capacity {\n",
     ["TST-M3-FAT32-BPB"], "SECURITY: a volume whose data region starts at or past its end is no longer refused by its own check: in the test kernel (overflow checks on) the cluster count's subtraction goes below zero and it panics; the release kernel's 64-bit subtraction wraps to a count the upper bound refuses. The panic (attempt to subtract with overflow) comes at the sector total0, after the line sector=fatsz16, exit 35, TST-M3-FAT32-BPB FAIL (seen locally)"),
    # M272: no upper bound on the cluster count.
    ("M272", "kernel/src/fs/fat32.rs",
     "        if !(65525..=0x0FFF_FFF5).contains(&clusters)\n",
     "        if clusters < 65525\n",
     ["TST-M3-FAT32-BPB"], "SECURITY: a volume of more than 0x0FFFFFF5 clusters mounts, so cluster numbers reach the bad mark and the end-of-chain marks: the lines carry sector=over_max|clusters=268435446|data_start=2097184 and sector=too_many|clusters=2147483615|data_start=2147483680, and the last refused=24|accepted=9|wrong=2, TST-M3-FAT32-BPB FAIL (seen locally on the case of 33 sectors)"),
    # M273 (SECURITY, from WP-106's red team): the FAT must hold an entry for every cluster number
    # up to the last, the two reserved entries included; without them a FAT one entry short passes.
    ("M273", "kernel/src/fs/fat32.rs",
     "            || (clusters + 2) * 4 > u64::from(fat_sectors) * SECTOR as u64\n",
     "            || clusters * 4 > u64::from(fat_sectors) * SECTOR as u64\n",
     ["TST-M3-FAT32-BPB"], "SECURITY: a FAT of 1008 sectors on a volume of 131071 sectors (129023 clusters, entries for 129025 numbers needed, 516100 bytes against 516096) mounts, and the last cluster's entry lies past the first FAT, in the second: the line carries sector=fat_small|clusters=129023|data_start=2048 and the last refused=25|accepted=8|wrong=1, TST-M3-FAT32-BPB FAIL (seen locally on the case of 33 sectors; the case as it was at 6673854b3, whose fat_small was two sectors short, passed under it)"),
    # M274 (SECURITY, from WP-106's red team): the mount judges the boot sector against a device of
    # any size, not the one it reads.
    ("M274", "kernel/src/fs/fat32.rs",
     "        Self::from_boot_sector(&b, block::capacity_sectors())\n",
     "        Self::from_boot_sector(&b, u64::MAX)\n",
     ["TST-M3-FAT32-BPB"], "SECURITY: a volume larger than its device mounts, so the kernel would address sectors past the disk: written to sector 0, the sectors spc8 (526280 sectors), big_fat (16842773) and max_ok (270532629) are mounted while the validation with the lab disk's 131072 sectors refuses them: their lines carry mount=0 and the last mount_same=30, TST-M3-FAT32-BPB FAIL (seen locally on the case of 33 sectors; the case as it was at 6673854b3, which compared the mount on the lab sector alone, passed under it)"),
    # M275 (SECURITY, from WP-106's close audit): the FAT's size in bytes is computed in 32 bits,
    # wrapping, so a FAT of 2^24 sectors or more is measured short.
    ("M275", "kernel/src/fs/fat32.rs",
     "            || (clusters + 2) * 4 > u64::from(fat_sectors) * SECTOR as u64\n",
     "            || (clusters + 2) * 4 > u64::from(fat_sectors.wrapping_mul(SECTOR as u32))\n",
     ["TST-M3-FAT32-BPB"], "SECURITY (the bound's own arithmetic, kept in 64 bits like the others; the wrapped size is never above the real one, so the mutant refuses volumes it should take and lets none through): the FAT's size in bytes wraps 32 bits, so a well-formed volume whose FAT is 2^24 sectors (2^33 bytes, wrapping to 0) is refused: the line carries sector=big_fat|refused=K_E_FS_BAD_BPB and the last refused=27|accepted=6|wrong=1, TST-M3-FAT32-BPB FAIL (seen locally; the case as it was at 695c5b5f0, with no FAT larger than 2097152 sectors, passed under it)"),
    # M276, M277 (WP-147, RSK-033): a write call on a stored first cluster that is no cluster of
    # the volume (1, or at or past its end) is refused before any disk write. M276 (SECURITY): the
    # guard without its test for 1.
    ("M276", "kernel/src/fs/fat32.rs",
     "        if file.first == 1 || file.first >= self.clusters + 2 {\n",
     "        if file.first >= self.clusters + 2 {\n",
     ["TST-M3-FAT32-BAD-FIRST"], "SECURITY: a write on an entry whose first cluster is 1 follows FAT entry 1: with the end mark the format left there it takes a cluster (five disk writes: both FAT copies, the zeroing, both FSInfo sectors) before it answers K_E_FS_CORRUPT, leaving the cluster lost; with entry 1 pointing at /HELLO.TXT's cluster it writes the bytes into that file and answers success; under a full volume it answers disk-full: the line carries one_writes=5, one_empty=0, one_link=512, one_link_writes=2, hello_ok=0 and one_full=K_E_FS_DISK_FULL, TST-M3-FAT32-BAD-FIRST FAIL (seen locally; the host checks then name a lost cluster and /HELLO.TXT's bytes)"),
    # M277 (not SECURITY): the guard without its test for the end. A write of bytes on such an
    # entry is still refused before any disk write, by the FAT read's own bound; only the empty
    # write, which asks the volume nothing, answers 0.
    ("M277", "kernel/src/fs/fat32.rs",
     "        if file.first == 1 || file.first >= self.clusters + 2 {\n",
     "        if file.first == 1 {\n",
     ["TST-M3-FAT32-BAD-FIRST"], "an empty write on an entry whose first cluster lies past the volume's end answers 0 instead of K_E_FS_CORRUPT; nothing is written and nothing else changes: the line carries past_end_empty=0 and far_empty=0, TST-M3-FAT32-BAD-FIRST FAIL (seen locally)"),
    # M278, M279 (not SECURITY): the end's test moved by one number. M278, one too high: the
    # first number past the last cluster escapes the guard, and only its empty write shows it.
    ("M278", "kernel/src/fs/fat32.rs",
     "        if file.first == 1 || file.first >= self.clusters + 2 {\n",
     "        if file.first == 1 || file.first > self.clusters + 2 {\n",
     ["TST-M3-FAT32-BAD-FIRST"], "an empty write on an entry whose first cluster is the first number past the volume's last cluster answers 0 instead of K_E_FS_CORRUPT; its write of bytes is still refused before any disk write by the FAT read's own bound and nothing else changes: the line carries past_end_empty=0 with far_empty=K_E_FS_CORRUPT, TST-M3-FAT32-BAD-FIRST FAIL (seen locally)"),
    # M279, one too low: the volume's last cluster number is refused as a first cluster. Written
    # `> self.clusters`, the form of `>= self.clusters + 1` the lint accepts.
    ("M279", "kernel/src/fs/fat32.rs",
     "        if file.first == 1 || file.first >= self.clusters + 2 {\n",
     "        if file.first == 1 || file.first > self.clusters {\n",
     ["TST-M3-FAT32-BAD-FIRST"], "a write call on an entry whose first cluster is the volume's last cluster is refused: the case's empty write on that number answers K_E_FS_CORRUPT instead of 0, and the line carries last_empty=K_E_FS_CORRUPT, TST-M3-FAT32-BAD-FIRST FAIL (seen locally)"),
    # M280 (not SECURITY; from the red team's pass): the guard's place before the range check.
    # The guard is silent when the offset is past the stored size, as if it stood after that
    # check: nothing is written either way, only the answer changes.
    ("M280", "kernel/src/fs/fat32.rs",
     "        if file.first == 1 || file.first >= self.clusters + 2 {\n",
     "        if (file.first == 1 || file.first >= self.clusters + 2) && offset <= file.size {\n",
     ["TST-M3-FAT32-BAD-FIRST"], "a write call whose offset is past the stored size, on an entry whose first cluster is 1, is answered by the range error instead of the corrupt-volume error; no disk write either way: the line carries one_past=K_E_FS_RANGE, TST-M3-FAT32-BAD-FIRST FAIL (seen locally)"),
    # M281 (SECURITY, WP-149, RSK-040, syscall.md v1.14): vmo_map asks READ for a mapping for
    # writing too, since a writable page on x86 is readable (K-3); the READ is dropped again.
    ("M281", "kernel/src/syscall/mod.rs",
     "            need = Rights(need.0 | Rights::WRITE.0 | Rights::READ.0);\n",
     "            need = Rights(need.0 | Rights::WRITE.0);\n",
     ["TST-M3-VMO-MAP-RIGHTS"], "SECURITY: a handle with MAP and WRITE and no READ maps the object for writing and reads its bytes through that mapping (K-3): the line carries write_noread=mapped and leak=1, TST-M3-VMO-MAP-RIGHTS FAIL (seen locally)"),
    # M282..M286 (WP-130, RSK-038): this harness's own worktree and the removal of a killed run's
    # leftovers, killed by TST-M0-005's EvidenceFreeWorktree cases. Each new text keeps its old
    # text inside it and each anchor below is split in two literals, so TST-M0-005's anchor guard
    # still finds every anchor once in the mutated harness: the kill is those cases' alone.
    ("M282", "tests/mutants.py", 'n != "evi' 'dence"', 'n != "evi' 'dence" or n',
     ["TST-M0-005"], "the run's worktree checks evidence/ out with every other tree (11 GB on disk on 2026-11-15)"),
    ("M283", "tests/mutants.py", "\n    remove_stale_" "worktrees()", "\n    remove_stale_" "worktrees() if False else None",
     ["TST-M0-005"], "a killed run's worktree and temporary directory are never removed at the next start"),
    ("M284", "tests/mutants.py", 'if lock_held(tmp / "lo' 'ck")', 'if lock_held(tmp / "lo' 'ck") and False',
     ["TST-M0-005"], "the removal at start ignores the lock and removes the worktree of a run that is still alive"),
    ("M285", "tests/mutants.py", "tmp.parent.resolve() != root or not tmp.name.starts" "with(PREFIX)",
     "False and (tmp.parent.resolve() != root or not tmp.name.starts" "with(PREFIX))",
     ["TST-M0-005"], "the removal at start takes every linked worktree of the repository, outside the harness's root and prefix too"),
    ("M286", "tests/mutants.py", 'lock = hold_lock(tmp / "lo' 'ck")', 'lock = hold_lock(tmp / "lo' 'ck"); lock.close()',
     ["TST-M0-005"], "a run lets its lock go at once, so another run's start removes its worktree while it runs"),
    # M287 (WP-151, L-016): import-ci-evidence stages the new run directories alone; the new text
    # keeps the anchor inside it, so the anchor occurs once in the mutated file too.
    ("M287", "tools/project.py", '"".join(f"evidence/{n}\\0" for n in new)',
     '"evidence\\0" if new else "".join(f"evidence/{n}\\0" for n in new)',
     ["TST-M0-007"], "the import checks the evidence branch's whole tree out again (13.7 GB on 2026-11-17), the directories already under evidence/ with the new ones"),
    # M288..M295 (WP-98): the merge of the gate's shard reports and the shard rule, killed by
    # TST-M0-005's ShardSelection and ShardMerge cases; as for M282..M286 each new text keeps its
    # anchor inside it and each anchor below is split in two literals. M288 is also stopped by the
    # union check, so the named reason kills it.
    ("M288", "tests/mutants.py", 'raise MergeRefused(f"shard {k}/{n} is miss' 'ing ({rel})")',
     'continue  # raise MergeRefused(f"shard {k}/{n} is miss' 'ing ({rel})")',
     ["TST-M0-005"], "the merge skips a missing shard report instead of refusing it by name"),
    ("M289", "tests/mutants.py", "if mid in wh" "ere", "if mid in wh" "ere and False",
     ["TST-M0-005"], "SECURITY (L-021): the merge accepts an id decided twice in a shard and keeps its later entry (a survivor's entry followed by a killed one hides it)"),
    ("M290", "tests/mutants.py", "summarize(mer" "ged)", 'summarize(mer' 'ged); merged["survived"] = reports[-1][2]["survived"]',
     ["TST-M0-005"], "SECURITY: the union's survivors are the last shard's alone, so a SECURITY survivor of another shard passes the gate"),
    ("M291", "tests/mutants.py", "verdict = gate_verdict(mer" "ged)",
     "verdict = gate_verdict(mer" "ged) or any(gate_verdict(dict(r)) for _, _, r in reports)",
     ["TST-M0-005"], "SECURITY: the gate passes when any shard passes on its own mutants, whatever the union's verdict"),
    ("M292", "tests/mutants.py", 'if r.get("run") != ' 'me', 'if r.get("run") != ' 'me and False',
     ["TST-M0-005"], "SECURITY: the merge takes shard reports of another run, attempt or sha (an older run's PASS)"),
    ("M293", "tests/mutants.py", "if set(where) != " "set(want)", "if set(where) != " "set(want) and False",
     ["TST-M0-005"], "SECURITY (L-021): the merge judges a union that is not the stage's mutants (a mutant in no shard, a SECURITY one too, is never run nor counted)"),
    ("M294", "tests/mutants.py", "% n == k" " - 1", "% n == k" " - 1 + 1",
     ["TST-M0-005"], "the shard rule is off by one: the mutants whose number is a multiple of N are in no shard"),
    ("M295", "tests/mutants.py", "if gate_shards is not " "None",
     "if gate_shards is not " "None and (REPO / shard_report(a.report, 1, 1)).parent.is_dir()",
     ["TST-M0-005"], "NAWAH_GATE_SHARDS set without its shard directory falls back to a full run instead of refusing"),
    # M296, M297 (SECURITY, WP-98, the audit of WP-96): two new run directories of one test id are
    # adopted or imported in turn and the last one's verdict stands, killed by TST-M0-007.
    ("M296", "tools/project.py", "clash = test_id_clash(found)", "clash = test_id_clash(found) and None",
     ["TST-M0-007"], "SECURITY: adopt-native adopts two new runs of one test id and the last one's verdict stands (a PASS covers a FAIL)"),
    ("M297", "tools/project.py", "clash = test_id_clash(new)", "clash = test_id_clash(new) and None",
     ["TST-M0-007"], "SECURITY: import-ci-evidence imports two new runs of one test id and the last one's verdict stands (a PASS covers a FAIL)"),
    ("M298", "tests/mutants.py", "summarize(mer" "ged)",
     'summarize(mer' 'ged); merged["ratio"] = sum(r["ratio"] for _, _, r in reports) / len(reports)',
     ["TST-M0-005"], "the union's ratio is the mean of the shards' ratios, not killed over valid counted over the union"),
    ("M299", "tests/mutants.py", 'if r["shard"].get("comp' 'lete") is not True',
     'if r["shard"].get("comp' 'lete") is not True and False',
     ["TST-M0-005"], "SECURITY (from the WP-98 review): the merge takes a shard whose run never finished (every mutant decided, then the final reset raised or the shard was stopped), so a gate FAIL can read as PASS"),
    # M300..M303 (WP-152): the gate's shard wiring in verify.yml, tooling mutants killed by
    # TST-M0-003 (MutationJob, MergeJob); each anchor occurs once in the clean file.
    ("M300", ".github/workflows/verify.yml", "    needs: [shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11, shard-12]\n",
     "    needs: [shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11]\n",
     ["TST-M0-003"], "job g no longer waits for shard 12: it can merge before that shard's report exists"),
    ("M301", ".github/workflows/verify.yml", '          NAWAH_GATE_SHARDS: "12"\n', '          NAWAH_GATE_SHARDS: "11"\n',
     ["TST-M0-003"], "job g merges eleven shard reports where twelve shard jobs ran"),
    ("M302", ".github/workflows/verify.yml",
     "    needs: [shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11, shard-12]\n    if: ${{ !cancelled() }}",
     "    needs: [shard-1, shard-2, shard-3, shard-4, shard-5, shard-6, shard-7, shard-8, shard-9, shard-10, shard-11, shard-12]\n    if: always()",
     ["TST-M0-003"], "SECURITY: job g runs and writes the gate's verdict in a cancelled run (always() instead of !cancelled())"),
    ("M303", ".github/workflows/verify.yml",
     "        run: python3 -I tests/mutants.py --target pc-qemu --stage M6 --report build/mutants-m6-report.json --shard 1/12\n",
     "        run: python3 tools/project.py test --target host --suite M6-GATE\n",
     ["TST-M0-003"], "shard 1 runs the gate suite as a case: the whole gate and a second TST-M6-MUTANTS verdict beside g's"),
    # M304 (WP-152, L-023): the run's own record of the shard count it ran under.
    ("M304", "tools/project.py", "    if shards is not None", "    if shards is not None and False",
     ["TST-M0-007"], "a run written under NAWAH_GATE_SHARDS no longer says so in run.json: job g's TST-M6-MUTANTS evidence reads as a whole run of the gate"),
    # M309..M314 (WP-153, the run's critical path): job b, the slots' uploads of this run's
    # directories alone and the merge's slots, in verify.yml; TST-M0-003 (TestJobs, MergeJob).
    ("M309", ".github/workflows/verify.yml",
     "        env:\n          NAWAH_SCRATCH_EVIDENCE: ${{ runner.temp }}/m5-build-evidence\n", "",
     ["TST-M0-003"], "job b's build writes TST-M1-BUILD into slot b beside job a's: two new runs of one test, the merge refuses the run"),
    ("M310", ".github/workflows/verify.yml", "            evidence/*-${{ steps.rev.outputs.sha8 }}-*-a/\n", "            evidence/*-a/\n",
     ["TST-M0-003"], "job a uploads every committed -a directory of older runs again, so its upload and the merge's download grow with every run"),
    ("M311", ".github/workflows/verify.yml",
     "(slot g, named by the checked-out commit's first 8 hex)\n        # Not the older runs' committed directories of the slot (WP-153: evidence/*-<slot>/ took them all).\n        id: rev\n        if: always()\n        run: echo \"sha8=$(git rev-parse HEAD | cut -c1-8)\"",
     "(slot g, named by the checked-out commit's first 8 hex)\n        # Not the older runs' committed directories of the slot (WP-153: evidence/*-<slot>/ took them all).\n        id: rev\n        if: always()\n        run: echo \"sha8=$(git rev-parse HEAD | cut -c1-7)\"",
     ["TST-M0-003"], "job g's step rev keeps 7 characters of the sha, so its pattern matches no run directory and slot g arrives empty"),
    ("M312", ".github/workflows/verify.yml",
     "          for slot in a b g; do\n            d=\"incoming/evidence-$slot/evidence\"",
     "          for slot in a g; do\n            d=\"incoming/evidence-$slot/evidence\"",
     ["TST-M0-003"], "the merge adopts slots a and g alone: job b's M5 verdicts never reach the records"),
    ("M313", ".github/workflows/verify.yml", "  b:\n    # WP-153: the M5 guest suite",
     "  b:\n    needs: [a]\n    # WP-153: the M5 guest suite",
     ["TST-M0-003"], "job b waits for job a: M5 runs after a again and the critical path is back"),
    ("M314", ".github/workflows/verify.yml",
     "      - name: M6 guest suite (release image interactive boot; test-kernel hold case)\n",
     "      - name: M5 guest suite again\n        run: python3 tools/project.py test --target pc-qemu --suite M5\n      - name: M6 guest suite (release image interactive boot; test-kernel hold case)\n",
     ["TST-M0-003"], "the M5 guest suite runs in job a too: two slots carrying its verdicts"),
    ("M315", ".github/workflows/verify.yml",
     "            evidence/*-${{ steps.rev.outputs.sha8 }}-*-b/\n            build/pc-qemu/build-id.txt\n",
     "            evidence/*-${{ steps.rev.outputs.sha8 }}-*-b/\n",
     ["TST-M0-003"], "job b's upload has its one evidence line again: the artifact is rooted at evidence/, the merge finds no incoming/evidence-b/evidence/ and fails every run (the WP-153 review)"),
    # M316, M317 (WP-95): mutants.yml's gates after the baseline alone, and a dispatch naming no
    # gate refused; TST-M0-003 (MutationHarness).
    ("M316", ".github/workflows/mutants.yml",
     "        if: ${{ !cancelled() && steps.baseline.outcome == 'success' && contains(format(' {0} ', inputs.stages || 'M2 M3 M4 M5'), ' M3 ') }}\n",
     "        if: always() && contains(format(' {0} ', inputs.stages || 'M2 M3 M4 M5'), ' M3 ')\n",
     ["TST-M0-003"], "the M3 gate runs under always() again, after a failed baseline, on an image that never built or booted"),
    ("M317", ".github/workflows/mutants.yml",
     "          if [ \"$n\" -eq 0 ]; then echo \"::error title=Stages::'$STAGES' selects no gate (M2 M3 M4 M5 M6)\"; exit 1; fi\n", "",
     ["TST-M0-003"], "a dispatch whose stages input names no gate runs no gate and ends green, with nothing to import"),
    # M318, M319 (WP-95, option B): mutants.yml's host suites and its job's limit.
    ("M318", ".github/workflows/mutants.yml", "          for s in M0 M1 M3 M4 M5 M6; do\n", "          for s in M0 M1 M3 M4 M6; do\n",
     ["TST-M0-003"], "mutants.yml's host suites drop M5: its tests stay stale on a head that changed them, the strict check fails and the run is never imported"),
    ("M319", ".github/workflows/mutants.yml", "    timeout-minutes: 345\n", "    timeout-minutes: 300\n",
     ["TST-M0-003"], "the mutants job's limit falls back to 300, under what a run of all five gates and the host suites needs: the job can end before its strict check and publish"),
    # M320..M322 (the WP-95 review): the stages step's character check, the artifact of this run's
    # directories alone, the host suites after the baseline alone.
    ("M320", ".github/workflows/mutants.yml",
     "            *[!M2-6\\ ]*) echo \"::error title=Stages::'$STAGES' holds a character other than M, 2 to 6 and a space\"; exit 1 ;;\n",
     "            *[!M2-6[:space:]]*) echo \"::error title=Stages::'$STAGES' holds a character other than M, 2 to 6 and a space\"; exit 1 ;;\n",
     ["TST-M0-003"], "the stages step lets a tab or a newline through: the shell's loop splits on it, every gate's contains(' M3 ') does not, and the run ends green with no gate"),
    ("M321", ".github/workflows/mutants.yml", "            evidence/*-${{ steps.rev.outputs.sha8 }}-*/\n", "            evidence/\n",
     ["TST-M0-003"], "the mutants artifact takes the whole tracked evidence tree again (14.4 GB), inside the job's unmeasured minutes"),
    ("M322", ".github/workflows/mutants.yml", "        if: ${{ !cancelled() && steps.baseline.outcome == 'success' }}\n", "        if: ${{ !cancelled() }}\n",
     ["TST-M0-003"], "the host suites run after a failed baseline, on a lab that never built or booted"),
    # M323 (WP-107, RSK-028; config.md v1.3): configd's one exit for the handle a request carried.
    # Without it every token stays in configd's table, a replay's too, and about a thousand such
    # requests fill it (it then reads nothing); TST-M4-CONFIG-RETRY reads the count while it lives.
    ("M323", "user/apps/configd/src/main.rs",
     "                if let Some(h) = handle.take() {\n                    libnawah::handle_close(h);\n                }\n",
     "",
     ["TST-M4-CONFIG-RETRY"], "SECURITY: configd keeps the handle every request carried, a replayed one's and one whose reply cannot be written included, so a manifest service fills its handle table and config stops reading"),
    # M324 (WP-156, RSK-028; services.md v1.13 note): the manager's CONNECT reply to a service,
    # written or the client end closed. As it was, a requester that cannot take its reply left the
    # client end in the manager's table and the target's slot taken; TST-M4-SVC-CONNECT-NOREAD
    # reads both live counts across three such requests.
    ("M324", "user/apps/svcmgr/src/main.rs",
     "                            if libnawah::channel_write(c, b\"OK\", &[client]) != 0 {\n                                libnawah::handle_close(client);\n                            }\n",
     "                            libnawah::channel_write(c, b\"OK\", &[client]);\n",
     ["TST-M4-SVC-CONNECT-NOREAD"], "SECURITY: the manager ignores that it could not write a service's CONNECT reply and keeps the client end, so a requester that never reads fills the manager's table and takes the target's client slots"),
    # M325, M326 (WP-157, RSK-028; config.md v1.4): a user store is created only for a token that
    # may modify it, judged from the name before a slot is taken, and never by SUBSCRIBE, which
    # shows no token. M325 creates it for any modifying request, so a refused SET or IMPORT leaves
    # the store loaded; M326 creates it for a subscriber, so eight of them take the eight slots
    # and the user's own SET is refused. TST-M4-CONFIG-STORE-AUTHZ reads both.
    ("M325", "user/apps/configd/src/main.rs",
     "        let Some(i) = self.store_index(name, create) else {\n",
     "        let Some(i) = self.store_index(name, true) else {\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "SECURITY: configd creates the user store a modifying request names before it judges the token, so a refused SET or IMPORT leaves a store loaded and eight of them take every user-store slot"),
    # M326 retired with WP-112 (config.md v1.6): SUBSCRIBE refuses every user store before it looks
    # one up, so creating one there is no longer reachable (an equivalent mutant); M437 guards the
    # refusal that replaced it.
    # M327 (WP-157): ADMIN is among the tokens a user store is created for (config.md §1). Not a
    # hole: without it an administrator is refused a store that is not loaded.
    ("M327", "user/apps/configd/src/main.rs",
     "            user_uid(name).is_some_and(|uid| token.perms & perm::ADMIN != 0 || uid == token.uid);\n",
     "            user_uid(name).is_some_and(|uid| uid == token.uid);\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "an administrator's SET on a user store that is not loaded is refused: the store is created for the user's own token alone"),
    # M328..M331 (WP-157's review round). M328: the check of a loaded user store, which the
    # refusals above no longer reach (a store that is not loaded is refused before it): without
    # it any token modifies another user's loaded store. M329, M330: the bounds of the uid a store
    # name may carry (1 to 9999): with 0 a subscriber is given an empty slot, and above the bound
    # the name is taken for a store. M331: no free slot for a token that may create is
    # ERR INVALID (config.md v1.4), not the refusal's ERR ACCESS.
    ("M328", "user/apps/configd/src/main.rs",
     "            _ => admin || self.stores[i].uid == token.uid,\n",
     "            _ => true,\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "SECURITY: configd lets any valid token modify a loaded user store, so one user overwrites another user's settings"),
    ("M329", "user/apps/configd/src/main.rs",
     "    (uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT)).then_some(uid as u32)\n",
     "    (uid <= u64::from(UID_MAX_PERSISTENT)).then_some(uid as u32)\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "user/0 names a store: a subscriber without a token is given an empty slot, whose subscription the next creation drops without closing its handle"),
    ("M330", "user/apps/configd/src/main.rs",
     "    (uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT)).then_some(uid as u32)\n",
     "    (uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT) * 10).then_some(uid as u32)\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "a uid above 9999 names a user store, whose file name the volume's rule does not allow"),
    ("M331", "user/apps/configd/src/main.rs",
     "            return Err(if create || user_uid(name).is_none() {\n",
     "            return Err(if user_uid(name).is_none() {\n",
     ["TST-M4-CONFIG-STORE-AUTHZ"], "a token that may create a user store is answered ERR ACCESS when no slot is free, as if it were refused"),
    # M332..M334 (WP-108, RSK-028; net.md parts B and C): netd frees a client's sockets and resets
    # its connections wherever it frees the client's slot, in one function. M332 is the
    # reply-failure path as it was (the slot freed, nothing else): whoever takes the slot next
    # reads the closed client's datagrams and holds its connection, and its port stays taken.
    # M333 is the same for a peer closed while idle. M334 leaves the connections out of the one
    # cleanup. TST-M4-NET-CLIENT-DROP reads all three.
    ("M332", "user/apps/netd/src/main.rs",
     "                if libnawah::channel_write(c, &out_buf[..len], &[]) == ERR_PEER_CLOSED {\n                    st.drop_client(ci);\n                }\n",
     "                if libnawah::channel_write(c, &out_buf[..len], &[]) == ERR_PEER_CLOSED {\n                    libnawah::handle_close(c);\n                    st.clients[ci] = 0;\n                }\n",
     ["TST-M4-NET-CLIENT-DROP"], "SECURITY: netd frees the slot of a client whose reply cannot be written and keeps its sockets and connections, so the next client in that slot reads its datagrams and holds its connection"),
    ("M333", "user/apps/netd/src/main.rs",
     "            Err(ERR_PEER_CLOSED) => st.drop_client(ci),\n",
     "            Err(ERR_PEER_CLOSED) => {\n                libnawah::handle_close(c);\n                st.clients[ci] = 0;\n            }\n",
     ["TST-M4-NET-CLIENT-DROP"], "SECURITY: netd frees the slot of a client that closed while idle and keeps its sockets and connections, so its ports stay taken and the next client in that slot inherits them"),
    ("M334", "user/apps/netd/src/main.rs",
     "            if self.conns[cn].owner == ci {\n                self.tcp_abort(cn);\n",
     "            if self.conns[cn].owner == ci && false {\n                self.tcp_abort(cn);\n",
     ["TST-M4-NET-CLIENT-DROP"], "SECURITY: a closed client's TCP connections are not reset, so the next client in its slot holds them"),
    # M335 (WP-108's review round): the cleanup takes the closed client's connections alone.
    ("M335", "user/apps/netd/src/main.rs",
     "            if self.conns[cn].owner == ci {\n                self.tcp_abort(cn);\n",
     "            if true {\n                self.tcp_abort(cn);\n",
     ["TST-M4-NET-CLIENT-DROP"], "SECURITY: one client's close resets every client's TCP connections"),
    # M336..M340 (WP-158, RSK-028; config.md v1.5): a subscription belongs to the client that
    # asked for it, one per client and store, and goes with the client; SUBSCRIBE session is
    # refused. M336: a client's second SUBSCRIBE takes another slot, so eight fill the store and
    # the next client is refused. M337: the one cleanup leaves the subscriptions. M339, M340: the
    # two paths that free a client's slot as they were, the client end closed and nothing else.
    # M338: SUBSCRIBE session accepted, so a subscriber without a token hears a session key.
    ("M336", "user/apps/configd/src/main.rs",
     "            .find(|&s| st.subs[s] != 0 && usize::from(st.sub_client[s]) == ci)\n",
     "            .find(|&s| st.subs[s] != 0 && false)\n",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: every SUBSCRIBE of one client takes another slot, so one client holds a store's eight subscriptions and the others are refused"),
    ("M337", "user/apps/configd/src/main.rs",
     "                if st.subs[s] != 0 && usize::from(st.sub_client[s]) == ci {\n                    libnawah::handle_close(st.subs[s]);\n",
     "                if st.subs[s] != 0 && false {\n                    libnawah::handle_close(st.subs[s]);\n",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: a client that has gone keeps its subscriptions in configd, a handle and a slot each"),
    ("M338", "user/apps/configd/src/main.rs",
     "                if store == b\"session\" {\n                    out.put(b\"ERR ACCESS\");\n                    return None;\n                }\n",
     "",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: SUBSCRIBE session is accepted without a token, so the subscriber hears the names and changes of every user's session keys"),
    ("M339", "user/apps/configd/src/main.rs",
     "                if sent == ERR_PEER_CLOSED {\n                    st.drop_client(ci);\n                }\n",
     "                if sent == ERR_PEER_CLOSED {\n                    libnawah::handle_close(c);\n                    st.clients[ci].chan = 0;\n                }\n",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: configd frees the slot of a client whose reply cannot be written and keeps its subscriptions"),
    ("M340", "user/apps/configd/src/main.rs",
     "            Err(ERR_PEER_CLOSED) => st.drop_client(ci),\n",
     "            Err(ERR_PEER_CLOSED) => {\n                libnawah::handle_close(c);\n                st.clients[ci].chan = 0;\n            }\n",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: configd frees the slot of a client that closed while idle and keeps its subscriptions"),
    # M342..M344 (WP-101, REQ-M6-004; services.md v1.14, ADR-0023): APPS and LAUNCH on a service's
    # boot channel are for the vouched session and desktop. M342: the requester is not checked,
    # so a plain service is given the registry and its LAUNCH is taken. M344: desktop is not
    # among the vouched. M343: an unknown request on a boot channel gets no reply, as before.
    ("M342", "user/apps/svcmgr/src/main.rs",
     "        if who != b\"session\" && who != b\"desktop\" {\n",
     "        if false {\n",
     ["TST-M6-LAUNCH-DENIED"], "SECURITY: the manager answers APPS and LAUNCH to any service, so a plain service reads the registry and asks for a launch"),
    ("M343", "user/apps/svcmgr/src/main.rs",
     "                    // repeated READY stays unanswered).\n                    libnawah::channel_write(c, b\"ERR BAD_REQUEST\", &[]);\n",
     "                    // repeated READY stays unanswered).\n",
     ["TST-M6-LAUNCH-DENIED"], "an unknown request on a service's boot channel gets no reply"),
    ("M344", "user/apps/svcmgr/src/main.rs",
     "        if who != b\"session\" && who != b\"desktop\" {\n",
     "        if who != b\"session\" {\n",
     ["TST-M6-LAUNCH-DENIED"], "the desktop is refused APPS and LAUNCH: the session alone is vouched"),
    # M345 (WP-101's review round): an entry enters the registry under its own file's name alone
    # (apps.md §4, FILE_NAME); the case's lab entry ZED.APP carries the id `other`.
    ("M345", "user/apps/svcmgr/src/main.rs",
     "            if let Ok(app) = one.add(file, &bytes[..n]) {\n",
     "            if let Ok(app) = nawah_apps::parse(&bytes[..n]) {\n",
     ["TST-M6-LAUNCH-DENIED"], "an entry is registered whatever its file is named, so a file that is not the id's own brings an application into the registry"),
    # M346..M357 (WP-161, REQ-M6-004; services.md v1.15, ADR-0023 item 1): the launch. The case's
    # line reads the applications the manager started (TST-M6-APP-SPAWN).
    ("M346", "user/apps/svcmgr/src/main.rs",
     "        match libnawah::process_spawn_in(job, elf, &[theirs]) {\n",
     "        match libnawah::process_spawn(elf, &[theirs]) {\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: an application is started in the manager's own job, the root, so ending the job made for it ends nothing and what it left behind stays"),
    ("M347", "user/apps/svcmgr/src/main.rs",
     "        match libnawah::process_spawn_in(job, elf, &[theirs]) {\n",
     "        match libnawah::process_spawn_in(job, elf, &[theirs, libnawah::handle_duplicate(self.root_job, libnawah::handle_rights(self.root_job) as u32).unwrap_or(0)]) {\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: an application is handed a copy of the root job beside its boot channel"),
    ("M348", "user/apps/svcmgr/src/main.rs",
     "        libnawah::job_kill(app.job);\n", "",
     ["TST-M6-APP-SPAWN"], "SECURITY: an application's job is not ended at its exit, so a process it started outlives it"),
    ("M349", "user/apps/svcmgr/src/main.rs",
     "const MAX_RUNNING: usize = 8;\n", "const MAX_RUNNING: usize = 9;\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: a ninth application is started: the table's bound is not the contract's"),
    ("M350", "user/apps/svcmgr/src/main.rs",
     "                    let taken = |a: &Running| a.process.is_some() && a.num == self.last_num;\n",
     "                    let taken = |_: &Running| false;\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: a number a running application carries is given again, so two applications run under one number"),
    ("M351", "user/apps/svcmgr/src/main.rs",
     "const APP_NUM_MAX: u8 = 99;\n", "const APP_NUM_MAX: u8 = 100;\n",
     ["TST-M6-APP-SPAWN"], "the circle of numbers ends at 100: an identity of three digits"),
    ("M352", "user/apps/svcmgr/src/main.rs",
     "                libnawah::handle_close(theirs);\n", "",
     ["TST-M6-APP-SPAWN"], "a launch that failed leaves the application's end of the channel in the manager's table"),
    ("M353", "user/apps/svcmgr/src/main.rs",
     "                libnawah::handle_close(ours);\n                libnawah::handle_close(job);\n",
     "                libnawah::handle_close(ours);\n",
     ["TST-M6-APP-SPAWN"], "a launch that failed leaves the job made for it"),
    ("M354", "user/apps/svcmgr/src/main.rs",
     "                if nh == 1 {\n                    libnawah::handle_close(hs[0]);\n                }\n                if let Some(name) = buf[..n].strip_prefix(b\"CONNECT \") {\n                    self.app_connect(a, c, name);\n",
     "                if let Some(name) = buf[..n].strip_prefix(b\"CONNECT \") {\n                    self.app_connect(a, c, name);\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: a handle an application sends on its boot channel stays in the manager's table"),
    ("M355", "user/apps/svcmgr/src/main.rs",
     "            Err(ERR_BUFFER_TOO_SMALL) if libnawah::channel_discard(c) => {}\n", "",
     ["TST-M6-APP-SPAWN"], "a message larger than a request closes the application's boot channel instead of being refused"),
    ("M356", "user/apps/svcmgr/src/main.rs",
     "        libnawah::handle_close(app.job);\n", "",
     ["TST-M6-APP-SPAWN"], "the handle of an application's job stays in the manager's table after its exit"),
    ("M357", "user/apps/svcmgr/src/main.rs",
     "        libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n    }\n\n    /// `CONNECT <name>` from application",
     "        let mut out = Out::new();\n        self.list(&mut out);\n        libnawah::channel_write(c, out.bytes(), &[]);\n    }\n\n    /// `CONNECT <name>` from application",
     ["TST-M6-APP-SPAWN"], "SECURITY: whatever an application asks on its boot channel is answered with the services' listing instead of being refused"),
    # M358..M361 (WP-161's review round, the red team's survivors): an application that closes
    # its boot channel and stays (the lab entry `closer`), and a request carrying two handles.
    ("M358", "user/apps/svcmgr/src/main.rs",
     "                libnawah::handle_close(c);\n                self.running[a].chan = None;\n",
     "                libnawah::handle_close(c);\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: an application that closes its boot channel ends the manager, which then waits on a closed handle"),
    ("M359", "user/apps/svcmgr/src/main.rs",
     "                libnawah::handle_close(c);\n                self.running[a].chan = None;\n",
     "                self.running[a].chan = None;\n",
     ["TST-M6-APP-SPAWN"], "the manager's end of a boot channel its application closed stays in the manager's table"),
    ("M360", "user/apps/svcmgr/src/main.rs",
     "        let Some(place) = self.running.iter().position(|a| a.process.is_none()) else {\n",
     "        let Some(place) = self.running.iter().position(|a| a.chan.is_none()) else {\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: the place of an application that closed its boot channel is given to another, so the first is watched no more and its job is never ended"),
    ("M361", "user/apps/svcmgr/src/main.rs",
     "        let Some(c) = self.running[a].chan else {\n            return;\n        };\n        let mut buf = [0u8; 64];\n        let mut hs = [0u32; 1];\n",
     "        let Some(c) = self.running[a].chan else {\n            return;\n        };\n        let mut buf = [0u8; 64];\n        let mut hs = [0u32; 4];\n",
     ["TST-M6-APP-SPAWN"], "SECURITY: a request of an application that carries two handles is read, and both stay in the manager's table"),
    # M362..M377 (WP-165, the owner's note of 2026-11-19): what docs/project-state.json says of the
    # next step and of the waiting decisions, in tools/project.py; killed by TST-M0-001.
    ("M362", "tools/project.py",
     "        task = next_in_order(by_id, order or [])\n",
     "        task = next((w for w in work_items if w[\"status\"] == \"planned\"\n                     and all(by_id.get(d, {}).get(\"status\") == \"done\" for d in w[\"depends_on\"])), None)\n",
     ["TST-M0-001"], "the next step is the file's first ready item again, whatever the owner's order names"),
    ("M363", "tools/project.py",
     "            if dep is None or dep[\"id\"] in path:\n                return w\n            w = dep\n",
     "            return w\n",
     ["TST-M0-001"], "an ordered item that waits for a dependency is written as the next step"),
    ("M364", "tools/project.py",
     "        ps[\"pending_decision_ids\"] = open_decisions(load_json(decisions)[\"records\"])\n",
     "        pass\n",
     ["TST-M0-001"], "a checkpoint leaves the list of waiting decisions as it was written by hand"),
    ("M365", "tools/project.py",
     "            (pb.err if strict else pb.warn)(\"project-state\", msg + \" (checkpoint pending)\")\n",
     "            pb.warn(\"project-state\", msg + \" (checkpoint pending)\")\n",
     ["TST-M0-001"], "a state file that contradicts the records passes the strict check"),
    ("M366", "tools/project.py",
     "                pb.err(w, f\"blocker names {dec}, which is not an open decision\")\n",
     "                pass\n",
     ["TST-M0-001"], "a work item keeps as its blocker a decision that was answered"),
    ("M367", "tools/project.py",
     "    return [d[\"id\"] for d in decisions if d[\"status\"] == \"open\"]\n",
     "    return [d[\"id\"] for d in decisions if d[\"status\"] != \"withdrawn\"]\n",
     ["TST-M0-001"], "an answered decision is listed as waiting for the owner"),
    ("M368", "tools/project.py",
     "        if value is not None or key == \"current_task\":\n",
     "        if value is not None:\n",
     ["TST-M0-001"], "with the whole order done a checkpoint leaves the last task as the current one"),
    ("M369", "tools/project.py",
     "        elif in_section and re.match(",
     "        elif re.match(",
     ["TST-M0-001"], "the order is read from the fifth item of any section of the methodology"),
    # M370..M377 (WP-165's review round): the forms of records and of the order's line that the
    # first cases did not have.
    ("M370", "tools/project.py",
     "            seen.add(w[\"id\"]); w = by_id.get(w.get(\"superseded_by\"))\n",
     "            seen.add(w[\"id\"]); w = None\n",
     ["TST-M0-001"], "a superseded item of the order hides the item that took its place"),
    ("M371", "tools/project.py",
     "    unfinished = lambda w: w is not None and w[\"status\"] != \"done\"\n",
     "    unfinished = lambda w: w[\"status\"] != \"done\"\n",
     ["TST-M0-001"], "an id the records do not hold stops the tool instead of being passed over"),
    ("M372", "tools/project.py",
     "for i in w[\"depends_on\"]) if unfinished(d)), None)\n",
     "for i in reversed(w[\"depends_on\"])) if unfinished(d)), None)\n",
     ["TST-M0-001"], "of two dependencies that are not done the last one written is the next step"),
    ("M373", "tools/project.py",
     "            in_section = line.startswith(\"## 7.\")\n",
     "            in_section = line.startswith(\"## 7\")\n",
     ["TST-M0-001"], "the order is read from a section whose number only begins with 7"),
    ("M374", "tools/project.py",
     "re.match(r\"5\\.\\s+\\*\\*الترتيب:\\*\\*\", line)",
     "re.match(r\"\\d+\\.\\s+\\*\\*الترتيب:\\*\\*\", line)",
     ["TST-M0-001"], "the order is read from any item of section 7 that carries the label"),
    ("M375", "tools/project.py",
     "        for dec in re.findall(r\"DEC-\\d+\", wi[\"blocker\"] or \"\"):\n",
     "        for dec in re.findall(r\"^DEC-\\d+$\", wi[\"blocker\"] or \"\"):\n",
     ["TST-M0-001"], "a decision named inside a blocker's text is not judged, only one named alone"),
    ("M376", "tools/project.py",
     "            if dep is None or dep[\"id\"] in path:\n",
     "            if dep is None:\n",
     ["TST-M0-001"], "a cycle of dependencies makes the tool run without end instead of ending where the cycle closes"),
    ("M377", "tools/project.py",
     "    head = f\"blocked ({task['blocker']}): \" if task[\"status\"] == \"blocked\" else \"\"\n",
     "    head = \"\"\n",
     ["TST-M0-001"], "a blocked item is written as the next step with no word that it is blocked"),
    # M140, M142, M378..M381 (WP-162, REQ-M6-004; services.md v1.16, ADR-0023 item 1): an
    # application's CONNECT, killed by TST-M6-APP-CONNECT-DENIED (the names `config` is given and
    # the applications' traces, required markers of the case).
    ("M140", "user/apps/svcmgr/src/main.rs",
     "            msg.put(b\"CONNECT app:\");\n",
     "            msg.put(b\"CONNECT \");\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: the service is told the application's id and number without the app: prefix, a name that can read as a service's"),
    ("M142", "user/apps/svcmgr/src/main.rs",
     "            .position(|d| d.as_bytes() == name)\n",
     "            .position(|d| d.as_bytes() == name)\n            .or(Some(1))\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: a name outside the allow-list is taken for config's place, so an application connects to the session"),
    ("M378", "user/apps/svcmgr/src/main.rs",
     "            .filter(|&b| self.app_deps[k] & (1 << b) != 0);\n",
     "            .filter(|_| true);\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: an application connects to an allowed service its entry does not declare"),
    ("M379", "user/apps/svcmgr/src/main.rs",
     "        if app.grants & (1 << b) != 0 || held >= APP_CONNECT_MAX {\n",
     "        if held >= APP_CONNECT_MAX {\n",
     ["TST-M6-APP-CONNECT-DENIED"], "an application is granted a second connection to the same service"),
    ("M380", "user/apps/svcmgr/src/main.rs",
     "const APP_CONNECT_MAX: usize = 4;\n",
     "const APP_CONNECT_MAX: usize = 5;\n",
     ["TST-M6-APP-CONNECT-DENIED"], "the running applications together are granted five connections to a service"),
    ("M381", "user/apps/svcmgr/src/main.rs",
     "                self.running[a].grants |= 1 << b;\n",
     "",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: a grant is not counted, so neither bound holds and applications take every place of a service"),
    # M382..M384 (WP-162's review round): the three single edits the red team found unkilled.
    ("M382", "user/apps/svcmgr/src/main.rs",
     "                self.running[a].grants |= 1 << b;\n",
     "                self.running[a].grants = 1 << b;\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: a grant replaces the one before, so an application declaring two services alternates between them without bound"),
    ("M383", "user/apps/svcmgr/src/main.rs",
     "                self.app_deps[self.apps_n] = app.deps.bits();\n",
     "                self.app_deps[self.apps_n] = 2;\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: every entry is taken to declare config alone, whatever it declares"),
    ("M384", "user/apps/svcmgr/src/main.rs",
     "                if libnawah::channel_write(c, b\"OK\", &[client]) != 0 {\n                    libnawah::handle_close(client);\n",
     "                if libnawah::channel_write(c, b\"OK\", &[client]) != 0 {\n",
     ["TST-M6-APP-CONNECT-DENIED"], "SECURITY: the client end an application could not take stays in the manager, one handle per full queue"),
    # M141, M385..M387 (WP-102, REQ-M6-004; services.md v1.17, ADR-0023 item 1): the session's
    # job, killed by TST-M6-SESSION-JOB (M385 by TST-M6-APP-SPAWN too).
    ("M141", "user/apps/svcmgr/src/main.rs",
     "            libnawah::job_kill(j);\n",
     "",
     ["TST-M6-SESSION-JOB"], "SECURITY: END_SESSION lets the session's job go without killing it, so the ended session's applications run on"),
    ("M385", "user/apps/svcmgr/src/main.rs",
     "        let Ok(job) = libnawah::job_create(session) else {\n",
     "        let Ok(job) = libnawah::job_create(self.root_job) else {\n",
     ["TST-M6-SESSION-JOB", "TST-M6-APP-SPAWN"], "SECURITY: an application's job is made under the root job, out of the session's reach"),
    ("M386", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() != b\"session\" {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        let n = ",
     "        if false {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        let n = ",
     ["TST-M6-SESSION-JOB"], "SECURITY: any vouched service, the desktop among them, ends the session"),
    ("M387", "user/apps/svcmgr/src/main.rs",
     "        if let Some(j) = self.session_job.take() {\n",
     "        if let Some(j) = self.session_job {\n",
     ["TST-M6-SESSION-JOB"], "the ended session's dead job is kept, so every later LAUNCH fails"),
    # M392..M395 (WP-102's review round): the single edits the red team and the auditor found
    # the case did not kill before it gained `sessions`, the start order and ENDED 1.
    ("M392", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() != b\"session\" {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        let n = ",
     "        if self.services[i].name() == b\"desktop\" {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        let n = ",
     ["TST-M6-SESSION-JOB"], "SECURITY: every vouched service but the desktop ends the session"),
    ("M393", "user/apps/svcmgr/src/main.rs",
     "            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        let n = ",
     "            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n        }\n        let n = ",
     ["TST-M6-SESSION-JOB"], "SECURITY: another service's END_SESSION is refused and the session ended all the same"),
    ("M394", "user/apps/svcmgr/src/main.rs",
     "        out.num(n as u64);\n",
     "        out.num(2);\n",
     ["TST-M6-SESSION-JOB"], "ENDED tells two applications whatever ran"),
    ("M395", "user/apps/svcmgr/src/main.rs",
     "                Ok(j) => *self.session_job.insert(j),\n",
     "                Ok(j) => j,\n",
     ["TST-M6-SESSION-JOB", "TST-M6-APP-SPAWN"], "SECURITY: each LAUNCH makes a session job of its own that END_SESSION never sees, so the applications outlive the session"),
    # M388, M389, M396 (WP-167, REQ-M6-004; session.md v1.8): Sign out ends the session's job,
    # killed by TST-M6-LOGOUT-KILLS.
    ("M388", "user/apps/sessiond/src/main.rs",
     "        if !self.boot_send(b\"END_SESSION\", BootOp::End) {\n            libnawah::trace(b\"session|jobs=unsent\");\n        }\n",
     "",
     ["TST-M6-LOGOUT-KILLS"], "SECURITY: Sign out asks the manager for nothing, so the signed-out session's applications run on into the next"),
    ("M389", "user/apps/sessiond/src/main.rs",
     "            Some(n) => t.put(b\"session|jobs=ended|apps=\").put(n),\n",
     "            Some(_) => t.put(b\"session|jobs=ended|apps=\").put(b\"0\"),\n",
     ["TST-M6-LOGOUT-KILLS"], "the session traces that no application was ended whatever the manager answered"),
    ("M396", "user/apps/sessiond/src/main.rs",
     "        self.boot_ops[k] = Some(op);\n",
     "        self.boot_ops[k] = Some(BootOp::Connect);\n",
     ["TST-M6-LOGOUT-KILLS"], "the manager's answer to END_SESSION is taken for a CONNECT's, so its outcome is never traced (the job is ended all the same)"),
    # M397..M400 (WP-164, RSK-050; syscall.md v1.15): a job holds 32 live processes at most,
    # killed by TST-M6-JOB-BOUND.
    ("M397", "kernel/src/object/job.rs",
     "        if !self.is_root() && self.procs.load(Ordering::SeqCst) >= JOB_PROCESSES_MAX {\n",
     "        if false {\n",
     ["TST-M6-JOB-BOUND"], "SECURITY: no job is bounded, so one application takes every kernel stack"),
    ("M398", "kernel/src/sched/mod.rs",
     "            Some(o) => match o.job().admit() {\n",
     "            Some(_) => match crate::object::job::root().admit() {\n",
     ["TST-M6-JOB-BOUND"], "SECURITY: every process is counted in the root, which has no bound"),
    ("M399", "kernel/src/object/job.rs",
     "        self.0.procs.fetch_sub(1, Ordering::SeqCst);\n",
     "",
     ["TST-M6-JOB-BOUND"], "a reaped process keeps its place, so a job that reached the bound never starts again"),
    ("M400", "kernel/src/object/job.rs",
     "self.procs.load(Ordering::SeqCst) >= JOB_PROCESSES_MAX {",
     "self.procs.load(Ordering::SeqCst) > JOB_PROCESSES_MAX {",
     ["TST-M6-JOB-BOUND"], "a job holds 33 processes, one more than the bound"),
    # M401..M405 (WP-163, REQ-M6-004; services.md v1.18): LAUNCH is bounded in rate, killed by
    # TST-M6-LAUNCH-RATE (M405 from the review round's red team).
    ("M401", "user/apps/svcmgr/src/main.rs",
     "        *oldest = Some(now);\n",
     "",
     ["TST-M6-LAUNCH-RATE"], "SECURITY: no attempt is kept, so LAUNCH is never refused for its rate and a requester starts images as fast as it asks"),
    ("M402", "user/apps/svcmgr/src/main.rs",
     "            out.put(b\"ERR FULL\");\n            return;\n",
     "            out.put(b\"ERR FULL\");\n            self.launches[self.launch_next] = Some(libnawah::clock_ticks());\n            self.launch_next = (self.launch_next + 1) % LAUNCH_RATE_MAX;\n            return;\n",
     ["TST-M6-LAUNCH-RATE"], "a full table's refusal counts as an attempt, so retrying after Sign out fills the window"),
    ("M403", "user/apps/svcmgr/src/main.rs",
     "            out.put(b\"ERR BUSY\");\n            return;\n        }\n        *oldest = Some(now);\n",
     "            *oldest = Some(now);\n            self.launch_next = (self.launch_next + 1) % LAUNCH_RATE_MAX;\n            out.put(b\"ERR BUSY\");\n            return;\n        }\n        *oldest = Some(now);\n",
     ["TST-M6-LAUNCH-RATE"], "a refusal counts as an attempt, so a requester that retries is never let through"),
    ("M404", "user/apps/svcmgr/src/main.rs",
     "                Some(k) => self.launch(k, &mut out),\n                None => out.put(b\"ERR UNKNOWN\"),\n",
     "                Some(k) => self.launch(k, &mut out),\n                None if self.launches[self.launch_next].is_some_and(|t| libnawah::clock_ticks().saturating_sub(t) < LAUNCH_WINDOW) => out.put(b\"ERR BUSY\"),\n                None => out.put(b\"ERR UNKNOWN\"),\n",
     ["TST-M6-LAUNCH-RATE"], "an unknown id is answered ERR BUSY while the window is full, which the contract answers ERR UNKNOWN"),
    ("M405", "user/apps/svcmgr/src/main.rs",
     "            Err(e) => {\n                // Nothing was moved when the image is missing",
     "            Err(e) => {\n                self.launch_next = (self.launch_next + LAUNCH_RATE_MAX - 1) % LAUNCH_RATE_MAX;\n                self.launches[self.launch_next] = None;\n                // Nothing was moved when the image is missing",
     ["TST-M6-LAUNCH-RATE"], "SECURITY: a failed launch is not counted, so a requester repeats a missing or broken image, each a job, a channel and a read of up to 4 MiB, without limit"),
    # M406..M410 (WP-169, REQ-M6-004; services.md v1.19, session.md v1.9): LAUNCH needs an open
    # session, killed by TST-M6-SESSION-GATE (M410, the session's side, by TST-M6-LOGOUT-KILLS).
    ("M406", "user/apps/svcmgr/src/main.rs",
     "                Some(_) if !self.session_open => out.put(b\"ERR NO_SESSION\"),\n",
     "",
     ["TST-M6-SESSION-GATE"], "SECURITY: LAUNCH is answered whether a session is open or not, so an application starts before anyone signs in or after Sign out"),
    ("M407", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() != b\"session\" {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        self.session_open = true;\n",
     "        if self.services[i].name() != b\"session\" && self.services[i].name() != b\"desktop\" {\n            libnawah::channel_write(c, b\"ERR ACCESS\", &[]);\n            return;\n        }\n        self.session_open = true;\n",
     ["TST-M6-SESSION-GATE"], "SECURITY: the desktop opens the gate, so LAUNCH is answered while no one is signed in"),
    ("M408", "user/apps/svcmgr/src/main.rs",
     "        self.session_open = false;\n        if let Some(j) = self.session_job.take() {\n",
     "        if let Some(j) = self.session_job.take() {\n",
     ["TST-M6-SESSION-GATE"], "SECURITY: END_SESSION leaves the gate open, so a LAUNCH after Sign out makes a session the next user inherits"),
    ("M409", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() == b\"session\" {\n",
     "        if self.services[i].name() == b\"session\" && code != 0 {\n",
     ["TST-M6-SESSION-GATE"], "SECURITY: the session service's clean exit (a STOP, its channel closed) leaves the gate open, so the desktop launches while no session runs"),
    ("M411", "user/apps/svcmgr/src/main.rs",
     "        self.session_open = false;\n        if let Some(j) = self.session_job.take() {\n",
     "        if let Some(j) = self.session_job.take() {\n            self.session_open = false;\n",
     ["TST-M6-SESSION-GATE"], "SECURITY: END_SESSION closes the gate only when an application was launched, so a user who signs in and out without one leaves it open"),
    ("M412", "user/apps/svcmgr/src/main.rs",
     "                Some(_) if !self.session_open => out.put(b\"ERR NO_SESSION\"),\n",
     "                Some(_) if !self.session_open => {\n                    self.launches[self.launch_next] = Some(libnawah::clock_ticks());\n                    self.launch_next = (self.launch_next + 1) % LAUNCH_RATE_MAX;\n                    out.put(b\"ERR NO_SESSION\")\n                }\n",
     ["TST-M6-SESSION-GATE"], "a refusal for no session counts as a launch attempt, so LAUNCHes before sign-in refuse the signed-in user's first ERR BUSY"),
    ("M410", "user/apps/sessiond/src/main.rs",
     "                    if !self.boot_send(b\"BEGIN_SESSION\", BootOp::Begin) {\n                        libnawah::trace(b\"session|begin=unsent\");\n                    }\n",
     "",
     ["TST-M6-LOGOUT-KILLS"], "a sign-in begins no session, so every launch of the signed-in user is refused"),
    ("M413", "user/apps/sessiond/src/main.rs",
     "    if libnawah::channel_write(boot, b\"READY\", &[]) != 0 {\n        return 0xE5;\n    }\n    loop {\n",
     "    if libnawah::channel_write(boot, b\"READY\", &[]) != 0 {\n        return 0xE5;\n    }\n    let _ = s.boot_send(b\"BEGIN_SESSION\", BootOp::Begin);\n    loop {\n",
     ["TST-M6-LOGOUT-KILLS"], "SECURITY: the session begins one at boot, so the desktop launches on the sign-in screen"),
    ("M414", "user/apps/sessiond/src/main.rs",
     "        if !self.boot_send(b\"END_SESSION\", BootOp::End) {\n            libnawah::trace(b\"session|jobs=unsent\");\n        }\n",
     "        if !self.boot_send(b\"END_SESSION\", BootOp::End) {\n            libnawah::trace(b\"session|jobs=unsent\");\n        }\n        let _ = self.boot_send(b\"BEGIN_SESSION\", BootOp::Begin);\n",
     ["TST-M6-LOGOUT-KILLS"], "SECURITY: Sign out begins a session again, so the desktop launches on the sign-in screen and the next user inherits it"),
    # M415, M416 (WP-172, REQ-M6-004; services.md v1.20): the session service's exit ends the
    # session's job, killed by TST-M6-SESSION-GATE.
    ("M415", "user/apps/svcmgr/src/main.rs",
     "            if let Some(job) = self.session_job.take() {\n                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n            }\n",
     "",
     ["TST-M6-SESSION-GATE"], "SECURITY: the session's applications outlive the session service, and the next sign-in's user shares their job"),
    ("M416", "user/apps/svcmgr/src/main.rs",
     "                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n",
     "                libnawah::job_kill(job);\n                self.session_job = Some(job);\n",
     ["TST-M6-SESSION-GATE"], "the session's job is killed at the session's exit but kept, so the next session's launches go to a dead job"),
    # M417, M418 (WP-173, REQ-M6-004; services.md v1.20): the session's exit ends its job however it comes,
    # killed by TST-M6-SESSION-RESTART (a RESTART: exit 0x40, the manager's state stopping). A third, a kill
    # skipped while stopping, is killed by the same reading as M417 and not registered (their evidence is one).
    ("M417", "user/apps/svcmgr/src/main.rs",
     "            if let Some(job) = self.session_job.take() {\n                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n            }\n        }\n",
     "            if code == 0 {\n                if let Some(job) = self.session_job.take() {\n                    libnawah::job_kill(job);\n                    libnawah::handle_close(job);\n                }\n            }\n        }\n",
     ["TST-M6-SESSION-RESTART"], "SECURITY: the session's job is ended only at a clean exit, so a crashed, stopped or restarted session leaves its applications to the next one"),
    ("M418", "user/apps/svcmgr/src/main.rs",
     "            if let Some(job) = self.session_job.take() {\n                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n            }\n        }\n        let s = &mut",
     "            if let Some(job) = self.session_job {\n                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n            }\n        }\n        let s = &mut",
     ["TST-M6-SESSION-RESTART"], "the session's job is ended and its handle closed at the session's exit but kept, so the restarted session's launches fail"),
    # M419 to M421 (WP-173's review round): the crash path (a nonzero exit while ready, restarted
    # on failure), the gate after an unclean exit and the session's place in the manifest.
    ("M419", "user/apps/svcmgr/src/main.rs",
     "            if let Some(job) = self.session_job.take() {\n                libnawah::job_kill(job);\n                libnawah::handle_close(job);\n            }\n        }\n",
     "            if code == 0 || self.services[i].state == State::Stopping {\n                if let Some(job) = self.session_job.take() {\n                    libnawah::job_kill(job);\n                    libnawah::handle_close(job);\n                }\n            }\n        }\n",
     ["TST-M6-SESSION-RESTART"], "SECURITY: the session's job is ended at a clean exit or a stop alone, so a crashed session's applications pass to the session started again"),
    ("M420", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() == b\"session\" {\n            self.session_open = false;\n",
     "        if self.services[i].name() == b\"session\" {\n            self.session_open &= code != 0;\n",
     ["TST-M6-SESSION-RESTART"], "SECURITY: an unclean exit of the session leaves the gate open, so LAUNCH is answered before the next session begins"),
    ("M421", "user/apps/svcmgr/src/main.rs",
     "        if self.services[i].name() == b\"session\" {\n            self.session_open = false;\n",
     "        if i == 0 {\n            self.session_open = false;\n",
     ["TST-M6-SESSION-RESTART"], "SECURITY: the session's exit is known by its place in the manifest, not its name, so a session listed after another service closes nothing and kills nothing"),
    # M422 to M429 (WP-112, REQ-M4-004, config.md v1.6): a user store is read for its owner's or an
    # administrator's usable token alone, loaded on that read, and a refused read takes no slot.
    ("M422", "user/apps/configd/src/main.rs",
     "        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid) {\n",
     "        if reader.is_some_and(|_| false) {\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: any request reads and loads any user store, with no token or another user's"),
    ("M423", "user/apps/configd/src/main.rs",
     "        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid) {\n",
     "        if !reader.is_some_and(|t| t.uid == uid) {\n",
     ["TST-M4-CONFIG-READ-LOAD"], "an administrator is not found another user's store"),
    ("M424", "user/apps/configd/src/main.rs",
     "        let reader = token.filter(|t| t.usable());\n        if !reader",
     "        let reader = token;\n        if !reader",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a revoked or expired token still reads its user's store"),
    ("M425", "user/apps/configd/src/main.rs",
     "            self.stores[i] = NO_STORE;\n            Err(REPLY_NOT_FOUND)\n",
     "            Err(REPLY_NOT_FOUND)\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a read of a store no volume holds keeps its slot, so reads fill the table against the owners' writes"),
    ("M426", "user/apps/configd/src/main.rs",
     "                let persistent = token.uid != 0 && token.uid <= UID_MAX_PERSISTENT;\n",
     "                let persistent = false;\n",
     ["TST-M4-CONFIG-READ-LOAD"], "RESOLVE does not load the token's own user store, so a value on the volume is passed over"),
    ("M427", "user/apps/configd/src/main.rs",
     "            Some(uid) => self.user_store_for_read(uid, token),\n",
     "            Some(uid) => self\n                .user_store_for_read(uid, token)\n                .or_else(|_| self.store_index(name, false).ok_or(REPLY_NOT_FOUND)),\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a refused GET or EXPORT still reads a user store that is loaded"),
    ("M428", "user/apps/configd/src/main.rs",
     "            .ok_or(REPLY_INVALID)?;\n",
     "            .ok_or(REPLY_NOT_FOUND)?;\n",
     ["TST-M4-CONFIG-READ-LOAD"], "a read with no free slot is answered not found instead of ERR INVALID"),
    ("M429", "user/apps/configd/src/main.rs",
     "                match self.store_for_read(store, token) {\n                    Ok(i) => {\n",
     "                match self\n                    .store_for_read(store, token)\n                    .or_else(|_| self.store_index(store, false).ok_or(REPLY_NOT_FOUND))\n                {\n                    Ok(i) => {\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a refused EXPORT still lists a user store that is loaded"),
    # M430 to M437 (WP-112's review round): an unusable administrator's token, what a refused reader
    # learns of a full table, CONFIG_WRITE and a group of that uid, a loaded store when the table is
    # full, policy before the reader's store, the slots' generations kept by a read, and SUBSCRIBE.
    ("M430", "user/apps/configd/src/main.rs",
     "        let reader = token.filter(|t| t.usable());\n",
     "        let reader = token.filter(|t| t.usable() || t.perms & perm::ADMIN != 0);\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: an administrator's revoked or expired token still reads every user store"),
    ("M431", "user/apps/configd/src/main.rs",
     "        let reader = token.filter(|t| t.usable());\n",
     "        if !(3..STORES).any(|i| self.stores[i].uid == uid || self.stores[i].uid == 0) {\n            return Err(REPLY_INVALID);\n        }\n        let reader = token.filter(|t| t.usable());\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a refused reader is told the table is full and the store not loaded"),
    ("M432", "user/apps/configd/src/main.rs",
     "        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid) {\n",
     "        if !reader.is_some_and(|t| t.perms & (perm::ADMIN | perm::CONFIG_WRITE) != 0 || t.uid == uid) {\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a token with CONFIG_WRITE reads every user's store"),
    ("M433", "user/apps/configd/src/main.rs",
     "        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid) {\n",
     "        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid || t.gid == uid) {\n",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: a token whose group number is a user's uid reads that user's store"),
    ("M434", "user/apps/configd/src/main.rs",
     "        if let Some(i) = (3..STORES).find(|&i| self.stores[i].uid == uid) {\n            return Ok(i);\n",
     "        (3..STORES).find(|&i| self.stores[i].uid == 0).ok_or(REPLY_INVALID)?;\n        if let Some(i) = (3..STORES).find(|&i| self.stores[i].uid == uid) {\n            return Ok(i);\n",
     ["TST-M4-CONFIG-READ-LOAD"], "a loaded user store is refused to its owner and an administrator when the table is full"),
    ("M435", "user/apps/configd/src/main.rs",
     "                let load = persistent && self.find(POLICY, key, token.uid).is_none();\n",
     "                let load = persistent;\n",
     ["TST-M4-CONFIG-READ-LOAD"], "RESOLVE loads the token's store before it looks at policy, so a full table stands before a policy value"),
    ("M436", "user/apps/configd/src/main.rs",
     "        if self.load(i) {\n            Ok(i)\n",
     "        if self.load(i) {\n            self.stores[i].slot_gen = [0; 2];\n            Ok(i)\n",
     ["TST-M4-CONFIG-READ-LOAD"], "a store a read loaded forgets its slots' generations, so its first write overwrites its only intact slot"),
    ("M437", "user/apps/configd/src/main.rs",
     "                if user_uid(store).is_some() {\n                    out.put(REPLY_ACCESS);\n                    return None;\n                }\n",
     "",
     ["TST-M4-CONFIG-READ-LOAD"], "SECURITY: SUBSCRIBE, which shows no token, is accepted on a loaded user store, which tells that it is loaded and its keys"),
    # M341 (WP-158's review round): the cleanup goes through every store.
    ("M341", "user/apps/configd/src/main.rs",
     "        for st in self.stores.iter_mut() {\n            for s in 0..MAX_SUBS {\n",
     "        for st in self.stores.iter_mut().take(1) {\n            for s in 0..MAX_SUBS {\n",
     ["TST-M4-CONFIG-SUBS"], "SECURITY: a client that has gone keeps its subscriptions in every store but the first"),
    # M305..M308 (WP-152's follow-up, verify run 44218469147): the Toolchain step's fallback mirror and
    # the runner mirror's budget, in mutants.yml where each anchor is once (verify.yml repeats the
    # step in nine jobs, a and the shards under one identity check); TST-M0-003 (FallbackMirror).
    ("M305", ".github/workflows/mutants.yml",
     "sudo sed -i 's#://[a-z0-9.-]*\\.archive\\.ubuntu\\.com/#://archive.ubuntu.com/#g' ",
     "sudo sed -i 's#http://azure\\.archive\\.ubuntu\\.com/#http://archive.ubuntu.com/#' ",
     ["TST-M0-003"], "the fallback rewrites the Azure mirror alone: on the EC2 runners it changes nothing and retries the same slow mirror"),
    ("M306", ".github/workflows/mutants.yml", "/etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true", "2>/dev/null || true",
     ["TST-M0-003"], "the fallback's rewrite edits apt-mirrors.txt alone, so a mirror named in ubuntu.sources stays"),
    ("M307", ".github/workflows/mutants.yml", "if ! retry 100 sudo", "if ! retry 300 sudo",
     ["TST-M0-003"], "the runner's mirror gets 300 s tries again: the fallback starts after the step's cap is half gone"),
    ("M308", ".github/workflows/mutants.yml",
     "retry 300 sudo DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=60 install --download-only",
     "retry 100 sudo DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=60 install --download-only",
     ["TST-M0-003"], "the fallback's fetch gets 100 s tries: a slow download from archive.ubuntu.com dies before it ends"),
    # M214..M218 (SECURITY, WP-121, files.md v1.7, ADR-0014 item 8): a write the volume cannot
    # hold whole changes nothing. M214: the write no longer asks for the clusters it needs.
    ("M214", "kernel/src/fs/fat32.rs",
     "        if need > have && !self.has_free(need - have)? {\n",
     "        if need > have && !self.has_free(0)? {\n",
     ["TST-M3-FAT32-DISK-FULL"], "SECURITY: a write to an empty file that the volume cannot hold takes what is free, writes, answers no space and loses the clusters, and any process can repeat it: the line carries refused_writes and a free_delta that are not 0 and the host checks find lost clusters, TST-M3-FAT32-DISK-FULL FAIL"),
    # M215: the clusters a call needs are rounded down.
    ("M215", "kernel/src/fs/fat32.rs",
     "        let need = (offset + data.len() as u32).div_ceil(cluster_bytes as u32);\n",
     "        let need = (offset + data.len() as u32) / cluster_bytes as u32;\n",
     ["TST-M3-FAT32-DISK-FULL"], "SECURITY: a write that ends inside a cluster the file does not have passes the question, writes the sectors it has and then finds no cluster: the refused call wrote to the device, the line carries refused_writes that is not 0, TST-M3-FAT32-DISK-FULL FAIL"),
    # M216: the question accepts one free cluster fewer than the call needs.
    ("M216", "kernel/src/fs/fat32.rs",
     "        Ok(want == 0 || self.nth_free(want, self.alloc_end())?.is_some())\n",
     "        Ok(want <= 1 || self.nth_free(want - 1, self.alloc_end())?.is_some())\n",
     ["TST-M3-FAT32-DISK-FULL"], "SECURITY: a write that needs one cluster more than the volume has is let through, takes what is free and loses it: the line carries refused_writes and a free_delta that are not 0 and the host checks find lost clusters, TST-M3-FAT32-DISK-FULL FAIL"),
    # M217: the question asks for every cluster of the file, not for the ones it lacks.
    ("M217", "kernel/src/fs/fat32.rs",
     "        if need > have && !self.has_free(need - have)? {\n",
     "        if need > have && !self.has_free(need)? {\n",
     ["TST-M3-FAT32-DISK-FULL"], "SECURITY: a file that has clusters cannot be extended while fewer clusters are free than it would hold in all, though the volume holds the call: the line carries b_grow=K_E_FS_DISK_FULL, TST-M3-FAT32-DISK-FULL FAIL"),
    # M218: the clusters a file has are counted from its size, not along its chain.
    ("M218", "kernel/src/fs/fat32.rs",
     "        let have = self.chain_len(file.first, need)?;\n",
     "        let have = file.size.div_ceil(cluster_bytes as u32).min(need);\n",
     ["TST-M3-FAT32-DISK-FULL"], "SECURITY: a write into a cluster the chain already holds past the size is refused on a full volume, and on a chain shorter than its size the question would ask for too few: the line carries d_into=K_E_FS_DISK_FULL, TST-M3-FAT32-DISK-FULL FAIL"),
    # M239..M251 (WP-127): the host image check names the longer files and judges the second FAT
    # copy. M239: the first copy's longer files are compared by number only.
    ("M239", "tools/fat32.py",
     "        if expect_longer is not None and names(longer) != wanted(expect_longer):\n",
     "        if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check --faulted --expect-longer NAMES` accepts another file, or another number of extra clusters, along the first FAT copy as long as the count is the same: the host case on the two images with equal counts fails, TST-M3-FAT32-TOOL FAIL"),
    # M240: the second copy's longer files are not compared with what the case names.
    ("M240", "tools/fat32.py",
     "        elif names(longer_o) != wanted(expect_longer_second):\n",
     "        elif False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `--expect-longer-second` accepts any file longer than its size along the second FAT copy: the host case on the chain longer in the second copy alone fails, TST-M3-FAT32-TOOL FAIL"),
    # M241: a chain longer than its size along the second copy is no problem when no case names it.
    ("M241", "tools/fat32.py",
     "            problems += [f\"FAT{fat}: {name}: chain longer than size\" for name, _ in longer_o]\n",
     "            pass\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: with --faulted a file longer than its size along the second FAT copy alone, its extra cluster free in the first, passes: the host case fails, TST-M3-FAT32-TOOL FAIL"),
    # M242: the second copy's lost clusters are not compared with the number the case pins.
    ("M242", "tools/fat32.py",
     "        if expect_lost_second is not None and lost_o != expect_lost_second:\n",
     "        if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `--expect-lost-second K` accepts any number of clusters marked in the second FAT copy alone: the host case with a hundred of them fails, TST-M3-FAT32-TOOL FAIL"),
    # M246: the second copy's clusters in use are not gathered, so none is ever lost there.
    ("M246", "tools/fat32.py",
     "            if v and v != 0x0FFFFFF7:\n                in_use_other[fat].add(c)\n",
     "            if False:\n                in_use_other[fat].add(c)\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: the second FAT copy's lost clusters are counted as none whatever it holds: the host case with a hundred clusters marked there fails, TST-M3-FAT32-TOOL FAIL"),
    # M243: a pin on the first copy is taken without the second's.
    ("M243", "tools/fat32.py",
     "    if (any(pin is not None for pin in lost_pins) and any(pin is None for pin in lost_pins)) \\\n            or (allow_longer is not None and expect_longer is None) or (expect_longer is not None and expect_longer_second is None):\n",
     "    if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a case may pin one FAT copy's lost clusters or longer files and leave the other copy unjudged: the host case on the unpaired options fails, TST-M3-FAT32-TOOL FAIL"),
    # M244: every longer file is said to have one cluster too many.
    ("M244", "tools/fat32.py",
     "                    longer.append((name, n - (size + cluster_bytes - 1) // cluster_bytes))\n",
     "                    longer.append((name, 1))\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a file two clusters longer than its size is taken for one that is one cluster longer, so two different states meet the same pin: the host case on the two images fails, TST-M3-FAT32-TOOL FAIL"),
    # M245: the walk looks a cluster up in the chain's list again (its cost grows with the square).
    ("M245", "tools/fat32.py",
     "            if c >= img.clusters + 2 or c in seen:\n",
     "            if c >= img.clusters + 2 or c in got:\n",
     ["TST-M3-FAT32-TOOL"], "the walk of a chain costs the square of its length again: the host case on a file of the volume's size runs past its bound, TST-M3-FAT32-TOOL FAIL"),
    # M247..M250 (SECURITY, WP-127, from its red team): M247: the first copy's longer files are
    # compared with the names the second copy shows.
    ("M247", "tools/fat32.py",
     "        if expect_longer is not None and names(longer) != wanted(expect_longer):\n",
     "        if expect_longer is not None and names(longer_o) != wanted(expect_longer):\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `--expect-longer` is met by the files that are longer along the second FAT copy, whatever the first holds: the host case with one file longer in each copy alone fails, TST-M3-FAT32-TOOL FAIL"),
    # M248: --allow-longer counts the second copy's longer files.
    ("M248", "tools/fat32.py",
     "        if allow_longer is not None and len(longer) != allow_longer:\n",
     "        if allow_longer is not None and len(longer_o) != allow_longer:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `--allow-longer N` is met by N files longer along the second FAT copy alone: the host case with two such files and none in the first copy fails, TST-M3-FAT32-TOOL FAIL"),
    # M249: the clusters lost in both copies are not compared with the number the case pins.
    ("M249", "tools/fat32.py",
     "        if expect_lost_both is not None and lost_both != expect_lost_both:\n",
     "        if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: one cluster marked in the first FAT copy alone and another in the second alone pass for one cluster lost in both: the host case on the two images fails, TST-M3-FAT32-TOOL FAIL"),
    # M250: a name the second copy alone reaches is not reported.
    ("M250", "tools/fat32.py",
     "        problems += [f\"FAT{fat}: {name} is reached along this copy only\" for name in sorted(reached_o - reached)]\n",
     "        pass\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a directory whose chain is longer in the second FAT copy alone shows a name there that the first copy does not reach, and nothing names it: the host case fails, TST-M3-FAT32-TOOL FAIL"),
    # M251 (SECURITY, WP-127, from its second audit): a name the first copy reaches and the
    # second does not is not reported.
    ("M251", "tools/fat32.py",
     "        problems += [f\"FAT{fat}: {name} is not reached along this copy\" for name in sorted(reached - reached_o)]\n",
     "        pass\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: a directory whose chain is longer in the first FAT copy alone shows a name there that the second copy does not reach, and nothing names it: the host case fails, TST-M3-FAT32-TOOL FAIL"),
    # M212, M213 (SECURITY, WP-118): the exact numbers a fault case gives the host checker.
    # M212: any number of chains longer than their size is accepted once the case allows some.
    ("M212", "tools/fat32.py",
     "        if allow_longer is not None and len(longer) != allow_longer:\n",
     "        if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check --faulted --allow-longer N` accepts an image with another number of chains longer than their size: the host case on the longer chain fails, TST-M3-FAT32-TOOL FAIL"),
    # M213: the number of lost clusters a case expects is no longer compared.
    ("M213", "tools/fat32.py",
     "    if expect_lost is not None and lost != expect_lost:\n",
     "    if False:\n",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check --faulted --expect-lost K` accepts an image with another number of lost clusters: the host case on the lost cluster fails, TST-M3-FAT32-TOOL FAIL"),
    # M210, M211 (SECURITY, WP-118, files.md v1.6, ADR-0014 item 7): a failed write leaves the
    # shared node equal to the stored entry. M210: the node takes the new entry before it is stored.
    ("M210", "kernel/src/fs/fat32.rs",
     "        self.store_entry(&staged)?;\n        *file = staged;\n        Ok(done)",
     "        *file = staged;\n        self.store_entry(&staged)?;\n        Ok(done)",
     ["TST-M3-FAT32-FAULT-WRITE"], "SECURITY: a write whose entry write is refused leaves the node of every open ahead of the stored entry, and the same open reads bytes the name does not hold: the sweeps' lines carry node_differs and ghost that are not 0, TST-M3-FAT32-FAULT-WRITE FAIL"),
    # M211: a new file's node takes its first cluster as soon as it is allocated.
    ("M211", "kernel/src/fs/fat32.rs",
     "            staged.first = self.alloc_cluster()?;\n",
     "            staged.first = self.alloc_cluster()?;\n            file.first = staged.first;\n",
     ["TST-M3-FAT32-FAULT-WRITE"], "SECURITY: a write to a new file that fails after its first allocation leaves the node with a first cluster the stored entry does not have: the first sweep's line carries node_differs that is not 0, TST-M3-FAT32-FAULT-WRITE FAIL"),
    # M208, M209 (SECURITY, WP-105): the host image check is the judge of the fault cases; these
    # blind it. M208: two names on one cluster are no longer reported.
    ("M208", "tools/fat32.py",
     "            if c in owner:\n                strict.append(f\"{name} and {owner[c]} share cluster {c}\")\n                break",
     "            if c in owner:\n                break",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check` no longer names two names on one cluster: two directories on one cluster pass `check --faulted` (exit 0; without --faulted the lost cluster still fails it), and for files the cut chain is still refused as shorter than its size but the named finding is gone: the host cases on shared clusters fail, TST-M3-FAT32-TOOL FAIL"),
    # M209: a chain that runs into a free cluster is no longer reported.
    ("M209", "tools/fat32.py",
     "            if v == 0:\n                strict.append(f\"{name}: cluster {c} of its chain is free\")\n                break",
     "            if v == 0:\n                break",
     ["TST-M3-FAT32-TOOL"], "SECURITY: `check` no longer names a chain that runs into a free cluster: a directory on a freed cluster passes `check --faulted` (exit 0; without --faulted the lost cluster still fails it), and for files the cut chain is still refused as shorter than its size but the named finding is gone: the host cases on a free cluster in a chain fail, TST-M3-FAT32-TOOL FAIL"),
]

def stage_of(mid: str) -> str:
    """M01..M29 belong to the M2 gate (TST-M2-MUTANTS), M30..M49 to the M3 gate (TST-M3-MUTANTS),
    M50..M81 to the M4 gate (TST-M4-MUTANTS), M82..M129 to the M5 gate (TST-M5-MUTANTS, WP-38),
    M130.. to the M6 gate (TST-M6-MUTANTS, WP-90). Every stage returned here must have a gate
    suite in tools/project.py HOST_SUITES run by mutants.yml (TST-M0-005 GateMapping)."""
    n = int(mid[1:])
    return "M2" if n < 30 else ("M3" if n < 50 else ("M4" if n < 82 else ("M5" if n < 130 else "M6")))


# The M5 mutants that undo a security fix of the pre-gate review (WP-43) or of WP-41: the gate
# fails if any of them survives, whatever the kill ratio (the review's rule 1 of 2026-10-27).
# M122 (kill authority, syscall.md v1.11 §5), M126 (a dead compositor's pixels left on the
# frame, display.md v1.5) and M129 (a wedged service never killed nor restarted, services.md
# v1.7) undo protections of the same rank.
SECURITY = {"M82", "M83", "M84", "M85", "M86", "M87", "M88", "M89", "M90", "M91",
            "M95", "M96", "M98", "M99", "M100", "M101", "M105", "M106", "M107", "M112",
            "M122", "M126", "M129",
            # M6 (WP-45): the boot-mode gate (boot.md v1.1): without the hypervisor bit no fw_cfg
            # read (M130), only the key 1 selects the self-test (M131), and an interactive boot
            # never takes the self-test exit (M132).
            "M130", "M131", "M132",
            # M6 (WP-64, WP-73): a restarted session purges the lost one's windows (session.md v1.7,
            # M135); auth revokes the tokens of a lost session client (auth.md v1.2, M137).
            "M135", "M137",
            # M6 (WP-67): displayd's start-up hold fails closed on a LIST failure (display.md
            # v1.12): a fail-open hold lets keys reach a window before the session unlocks.
            "M147",
            # M6 (WP-64): the purge fails closed when the listing cannot be read (session.md v1.7).
            "M150",
            # M6 (WP-46): jobs (syscall.md v1.13 §5): WRITE gates every job call (M151), a child
            # inherits the caller's job so job_kill reaches what a member starts (M152), and no
            # process enters a killed job (M153).
            "M151", "M152", "M153",
            # M6 (WP-68): the manifest is read whole or refused (services.md v1.13, M157) and LOAD
            # reads only under /SYSTEM/ (M159). M158 (MANIFEST_IO) is not SECURITY.
            "M157", "M159",
            # M6 (WP-78): the config WRITE scope at the authority layer (files.md v1.4, M162-M164).
            "M162", "M163", "M164",
            # M6 (WP-49): libui menus (ui.md v1.6 §3.6): a disabled menu item is never chosen
            # (M168).
            "M168",
            # M6 (WP-80): libui confirm (ui.md v1.7 §3.7): Esc answers Cancel, never consent (M171).
            "M171",
            # M6 (WP-50 50a): the list view (ui.md v1.8 §3.8): a selection is by row id (M176),
            # typing never activates (M177), a denial is never shown as empty (M179), and bidi
            # controls in a cell are shown, never obeyed (M180).
            "M176", "M177", "M179", "M180",
            # M6 tooling (WP-82, WP-83): the console-transcript forbidden check (M174), adopt-native's
            # attempt and identity checks (M185, M186) and the merge job's guards (M187-M190).
            "M174", "M185", "M186", "M187", "M188", "M189", "M190",
            # M6 (WP-94): a described value never forges an attribute or a second line (M193).
            "M193",
            # M6 (WP-84): a failed manager always stops the interactive boot visibly (M172) and
            # the halt code says what happened (M173).
            "M172", "M173",
            # M6 (WP-99): a wait's deadline is kept beside a spinning thread, so the LOAD budget
            # holds against a manager that never blocks (M194).
            "M194",
            # M6 (WP-100): the registry parser refuses the reserved ids (apps.md v1 §3, M198).
            "M198",
            # M6 (WP-97): a window title cannot forge the compositor's narrator line
            # (display.md v1.14): in the focus line (M199) and in the resize line (M200).
            "M199", "M200",
            # M6 (WP-104): a disk request that timed out stops the device (ADR-0013 decision 9):
            # the next requests are refused (M201), a refused write leaves the shared buffer
            # alone (M202), a failed read hands nothing to its caller (M203) and a refused
            # request is not published first (M204).
            "M201", "M202", "M203", "M204",
            # M6 (WP-105): delete and truncate write the directory entry before they free the
            # chain (files.md v1.5): no name points at a freed cluster (M205, M206) and the
            # shared node follows the stored entry (M207).
            "M205", "M206", "M207",
            # M6 tooling (WP-105): the host image check that judges the fault cases still sees
            # shared clusters (M208) and a chain that runs into a free cluster (M209).
            "M208", "M209",
            # M6 (WP-118): a failed write leaves the shared node equal to the stored entry
            # (files.md v1.6): the node follows the stored entry (M210) and takes no cluster
            # before it (M211).
            "M210", "M211",
            # M6 tooling (WP-118): the host checker compares the exact numbers a fault case
            # gives it: chains longer than their size (M212) and lost clusters (M213).
            "M212", "M213",
            # M6 (WP-121): a write the volume cannot hold whole changes nothing (files.md v1.7):
            # the call asks for its clusters (M214), counts them rounded up (M215), is not let
            # through one short (M216), asks only for the ones the file lacks (M217) and counts
            # the ones it has along the chain (M218).
            "M214", "M215", "M216", "M217", "M218",
            # M6 (WP-120): the FAT copy the kernel reads is written last (files.md v1.8).
            "M219",
            # M6 (WP-117): the file system stops with the disk (files.md v1.9): fs::with asks
            # (M220), vfs::seek asks (M221) before it moves anything (M223), vfs::write answers
            # nothing from the node (M222) and the driver sets the flag they read (M224).
            "M220", "M221", "M222", "M223", "M224",
            # the system-call layer asks first for the eight calls of the files contract (M225).
            "M225",
            # M6 tooling (WP-126): the host image check names an entry with no cluster (M226,
            # M232), a directory's 0 too (M227, M236) but not an empty file's (M231), the
            # reserved value and a number past the volume in a chain (M228, M238), scans every
            # FAT copy (M229, M230, M235, M237) and
            # does both in plain mode as with --faulted (M233, M234).
            "M226", "M227", "M228", "M229", "M230", "M231", "M232", "M233", "M234", "M235", "M236", "M237", "M238",
            # M6 tooling (WP-127): the checker names the longer files (M239, M244), judges the second
            # FAT copy (M240, M241, M242, M246) and refuses a pin on the first without it (M243).
            "M239", "M240", "M241", "M242", "M243", "M244", "M246",
            # from WP-127's red team: each copy's longer files are its own (M247, M248), the clusters lost
            # in both copies are pinned (M249), a name along one copy only is named (M250, M251).
            "M247", "M248", "M249", "M250", "M251",
            # M6 (WP-124): a FAT write stops at its first refused write (M252, M253), and the hook
            # that shows it refuses one write alone (M254).
            "M252", "M253", "M254",
            # from WP-124's red team: the whole call stops at the refused write: no write after
            # it (M255), no swallowed FSInfo refusal (M256), no second try (M257).
            "M255", "M256", "M257",
            # M6 (WP-131): a write stops at its first refused disk write: the zeroing (M258),
            # the data (M259), and no write after the refused one (M260).
            "M258", "M259", "M260",
            # M6 (WP-133): a create that grows its directory stops at its first refused disk
            # write: the link of the directory's tail (M261) and the entry (M263). M262, the
            # order of those two writes, is not a security mutant.
            "M261", "M263",
            # from WP-133's red team: a new cluster is zeroed where it is, not beside it (M264).
            "M264",
            # M6 (WP-134): no disk write is asked for between a refused write of a growth and
            # the error (M265).
            "M265",
            # from WP-134's red team: the hook refuses one write alone for every N (M266), and a
            # refused zeroing is answered before any further write (M267).
            "M266", "M267",
            # from WP-138's red team: the second FAT copy does not link a directory's tail to a
            # new cluster before that cluster is zeroed (M268).
            "M268",
            # WP-106 (RSK-027): the mount's bounds on a boot sector, in 64 bits (M270-M272).
            "M270", "M271", "M272",
            # from WP-106's audit and red team: the FAT holds the two reserved entries too (M273),
            # and the mount judges against its own device's capacity (M274).
            "M273", "M274",
            # from WP-106's close audit: the FAT's size in bytes in 64 bits (M275).
            "M275",
            # WP-147 (RSK-033): a write call on a stored first cluster of 1 is refused before any
            # disk write (M276). M277, the end's test, only changes the empty write's answer.
            "M276",
            # WP-149 (RSK-040, K-3): a mapping for writing needs READ too (M281).
            "M281",
            # WP-98: the merge of the gate's shards judges the union of this run's reports alone
            # (M290, M291, M292), and two new runs of one test id are never adopted or imported
            # (M296, M297).
            "M290", "M291", "M292", "M296", "M297", "M299",
            # L-021 (WP-152): no survivor hidden behind a later entry (M289), no union that skips
            # a mutant, a SECURITY one included (M293).
            "M289", "M293",
            # WP-152: the gate's merge job never runs in a cancelled run (M302).
            "M302",
            # WP-95 (the audit the owner ordered, 2026-11-16): nine authority checks of M3 and M4,
            # outside the set until then: channel_write's WRITE right (M34), token minting (M53),
            # svcmgr's hand-over to auth and its connect rule (M62, M67), authd's password, attempt
            # limit and LOGOUT revocation (M68, M69, M70), configd's device-store authorization
            # (M73) and netd's no-internet policy (M77).
            "M34", "M53", "M62", "M67", "M68", "M69", "M70", "M73", "M77",
            # WP-107 (RSK-028): configd closes the handle every request carried, at one exit,
            # a replay's and one whose reply cannot be written included (config.md v1.3, M323).
            "M323",
            # WP-156 (RSK-028): the manager closes the client end of a connection whose reply
            # to the requesting service it could not write (services.md v1.13 note, M324).
            "M324",
            # WP-157 (RSK-028): configd creates a user store only for a token that may modify it
            # (M325) and never for a subscriber, which shows none (M326; config.md v1.4); a loaded
            # user store is modified by its own uid's token or ADMIN alone (M328).
            "M325", "M328",
            # WP-108 (RSK-028): netd frees a client's sockets and resets its connections on
            # every path that frees its slot, and those alone (net.md parts B and C; M332 to M335).
            "M332", "M333", "M334", "M335",
            # WP-158 (RSK-028): a subscription is its client's, one per client and store, and
            # goes with the client; no session subscription without a token (config.md v1.5).
            "M336", "M337", "M338", "M339", "M340", "M341",
            # WP-101 (REQ-M6-004): APPS and LAUNCH are answered to the vouched session and
            # desktop alone (services.md v1.14; M342).
            "M342",
            # WP-161 (REQ-M6-004): an application runs in a job of its own with its boot channel
            # alone, under a number of its own, eight at most, refused whatever it asks, and
            # its job ends with it (services.md v1.15).
            "M346", "M347", "M348", "M349", "M350", "M354", "M357", "M358", "M360", "M361",
            # WP-162 (REQ-M6-004): an application connects to its declared services alone,
            # vouched as app:<id>#<n>, within one grant each and four for all (services.md v1.16).
            "M140", "M142", "M378", "M381", "M382", "M383", "M384",
            # WP-102 (REQ-M6-004): the session's applications run in one job, which END_SESSION
            # from the session alone ends (services.md v1.17).
            "M141", "M385", "M386", "M392", "M393", "M395",
            # WP-167 (REQ-M6-004): Sign out ends the session's job (session.md v1.8).
            "M388",
            # WP-164 (RSK-050): a job holds 32 live processes at most (syscall.md v1.15).
            "M397", "M398",
            # WP-163 (REQ-M6-004): LAUNCH is bounded in rate (services.md v1.18).
            "M401", "M405",
            # WP-169 (REQ-M6-004): LAUNCH needs an open session (services.md v1.19).
            "M406", "M407", "M408", "M409", "M411", "M413", "M414",
            # WP-172 (REQ-M6-004): the session service's exit ends its job (services.md v1.20).
            "M415",
            # WP-173 (REQ-M6-004): however the session service exits (services.md v1.20).
            "M417", "M419", "M420", "M421",
            # WP-112 (REQ-M4-004): a user store is read for its owner or an administrator alone (config.md v1.6).
            "M422", "M424", "M425", "M427", "M429",
            # WP-112's review round: unusable admin, a full table told, CONFIG_WRITE, a group, SUBSCRIBE.
            "M430", "M431", "M432", "M433", "M437"}


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


# Every tree a mutant may touch (WP-90): the sources and the tooling that tests them. A tooling
# mutant left in place would run under every later mutant's killers.
RESTORED = ("kernel", "user", "tools", "tests", ".github")


def reset(wt: Path) -> None:
    """Restore every tree a mutant may touch, then prove it: a tracked path left modified (or
    staged) under RESTORED fails the run rather than leak into the next mutant (WP-90)."""
    subprocess.run(["git", "checkout", "-q", "--"] + list(RESTORED), cwd=wt, check=True)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--"] + list(RESTORED),
                           cwd=wt, check=True, capture_output=True, text=True).stdout.strip()
    if dirty:
        raise RuntimeError(f"reset left tracked changes in the worktree: {dirty}")


def is_tooling(rel: str) -> bool:
    """A mutant of the lab's tooling (tools/, tests/, .github/), not of the image: its killers are
    host cases, run through the worktree's tools/project.py; no image is built and no guest case
    is swept for it (WP-90)."""
    return Path(rel).parts[0] not in ("kernel", "user")


def needs_image(target, rel, killers) -> bool:
    """Whether the mutant's image is built before its declared killers run: only for a kernel or
    user mutant with at least one guest killer. A source mutant killed by host cases alone (libui's
    unit tests, TST-M0-003's source guards) builds the image only if the fairness sweep needs it."""
    return not is_tooling(rel) and any(suite_of(target, k) is not None for k in killers)


def crate_of(rel: str):
    """The cargo package a mutated file belongs to (for `--check`): the kernel, or a user crate,
    read from the crate's own Cargo.toml (the directory user/libnawah-text holds the package
    nawah-text: M115-M121 were INVALID on 2026-10-31 while the name was guessed from the path)."""
    parts = Path(rel).parts
    if parts[0] == "kernel":
        return None
    if parts[0] != "user":
        return None
    crate_dir = REPO / parts[0] / parts[1] / parts[2] if parts[1] == "apps" else REPO / parts[0] / parts[1]
    for line in (crate_dir / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("name"):
            return line.split("=", 1)[1].strip().strip('"')
    return None


# The driver that judges every killer is the clean checkout's tools/project.py (WP-90): HOST_SUITES,
# host-suite-of and the PASS/FAIL decision never come from the worktree, where a tooling mutant
# could judge itself (a mutated cmd_test_host_case printing OK). Only the case's own files are
# read from the worktree, through NAWAH_ROOT.
PYPROJ = ["python3", str(REPO / "tools" / "project.py")]


def host_suite_of(wt: Path, test_id):
    """The host suite of the clean tools/project.py that holds `test_id`, or None (`wt` is kept
    for the callers; the lookup never reads the worktree)."""
    r = subprocess.run(PYPROJ + ["host-suite-of", test_id], cwd=REPO, capture_output=True, text=True,
                       env={k: v for k, v in os.environ.items() if k != "NAWAH_ROOT"})
    return r.stdout.strip() or None if r.returncode == 0 else None


# A host killer's FAIL is a kill only when the case's test runner reached a verdict and reported
# failing tests (unittest `FAILED (...)`, cargo `test result: FAILED`), and the same case passes
# on the clean tree. A case that cannot start (its file does not compile or import, a missing
# tool, a timeout) or that also fails unmutated is ERROR: a kill must be caused by the mutant.
RUNNER_FAILED = re.compile(r"^(FAILED \(|test result: FAILED)", re.M)
_CLEAN_HOST = {}


def runner_reported_failures(out: str, env) -> bool:
    m = re.search(r" run=(\S+)", out)
    scratch = env.get("NAWAH_SCRATCH_EVIDENCE")
    if not m or not scratch:
        return False
    d = Path(scratch) / m.group(1)
    text = "".join((d / f).read_text(encoding="utf-8", errors="replace") for f in ("stdout.log", "stderr.log") if (d / f).exists())
    return bool(RUNNER_FAILED.search(text))


def passes_clean(env, host_suite, test_id) -> bool:
    """The host case on the clean checkout (cached per run)."""
    if test_id not in _CLEAN_HOST:
        r = sh(PYPROJ + ["test", "--target", "host", "--suite", host_suite, "--only", test_id], REPO,
               dict(env, NAWAH_ROOT=str(REPO)))
        _CLEAN_HOST[test_id] = r.returncode == 0
    return _CLEAN_HOST[test_id]


def suite_of(target, test_id):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    for suite, cases in t["suites"].items():
        if any(c["id"] == test_id for c in cases):
            return suite
    return None


def _write_report(rel, report):
    """Write the report as it stands, so a run killed by the gate timeout still leaves every
    mutant decided so far on disk (the M5 gate hit its 10800 s limit on 2026-10-31 and left no
    report at all)."""
    rp = REPO / rel
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=1) + "\n")


def needs_release(target, killers):
    """Whether a declared killer boots the release image NAWAH.EFI (a case without its own
    artifact boots the build's, NAWAH.EFI): then the mutant's release kernel is built before
    the killers run. Keyed on TST-M1-BOOT alone, TST-M6-INTERACTIVE-BOOT found no artifact
    (SKIPPED) and, being declared, was left out of the fairness sweep too."""
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    default = t["build"]["artifact"]
    cases = {c["id"]: c for cs in t["suites"].values() for c in cs}
    return any(k in cases and cases[k].get("artifact", default) == "${OUT}/NAWAH.EFI" for k in killers)


# Kill evidence (the owner's audit of WP-138): a killer's FAIL alone does not say why it failed (a
# timeout, a setup failure and the failure of the field a mutant is about all read "killed"), and
# the scratch evidence is deleted right after each mutant. run_killers keeps, for every FAIL, the
# driver's reason, the run id and the test kernel's `|ktest|` lines of that run (the last
# KILL_LINES of each boot, each cut at KILL_LINE_CHARS) in KILLS; main() copies them into the
# mutant's report entry and prints them under its line before the scratch is emptied.
KILLS = {}
KILL_LINES = 12
KILL_LINE_CHARS = 600
KILL_REASON_CHARS = 1000

# Declared expectations: {mutant id: {declared killer: [substring, ...]}}. Every substring must
# occur in that killer's kept reason + "\n" + its kept lines, or the mutant is `expected_missed`
# and the run fails whatever the ratio: a kill that cannot be shown to be the declared one does
# not pass the gate. The strings are the lines the test kernel printed for each kill.
_NAMES = "|ktest|fail|after a create under the hook the two FAT copies do not list the same names in the directory"
_FREE = "|ktest|fail|after a create under the hook the directory's chain along the second FAT copy stands on a cluster that is free there"
_BPB = "|ktest|fat32_bpb|sector="
_JUDGED = "|ktest|fail|a boot sector was not judged as expected"
_UNREFUSED = "|ktest|fail|a write on an entry whose first cluster is no cluster of the volume was not refused before any disk write"
_LAST = "|ktest|fail|an empty write on an entry whose first cluster is the volume's last was not answered 0 with no disk write"
_PAST = "|ktest|fail|a write past the stored size on an entry whose first cluster is 1 was not answered by the corrupt-volume error with no disk write"
_K3 = "|ktest|fail|a handle without READ was not refused a mapping for writing with ERR_ACCESS"
_KEPT = "|ktest|fail|configd kept the handles its replayed requests carried"
_HELD = "|ktest|fail|the manager kept the client ends whose CONNECT replies it could not write"
_LEFT = "|ktest|fail|a refused write left a user store behind"
_TOOK = "|ktest|fail|a subscriber without a token took a user store"
_ADMIN = "|ktest|fail|an administrator was refused a user's store"
_LOADED = "|ktest|fail|a write on another user's loaded store was not refused"
_NONAME = "|ktest|fail|a name that is no user store was not answered ERR INVALID"
_FULLTAB = "|ktest|fail|a full table of user stores was not answered as the contract says"
_USED = "|ktest|fail|a later client used the socket or the connection of a client that had closed"
_IDLE = "|ktest|fail|an idle client's close left its socket behind"
_OTHER = "|ktest|fail|a client's close reset another client's connection"
_MANY = "|ktest|fail|one client held more than one subscription of a store"
_SUBSTAY = "|ktest|fail|a closed client's subscription stayed"
_ZSTAY = "|ktest|fail|the subscription of a client whose reply could not be written stayed"
_SESS = "|ktest|fail|a subscriber without a token heard a session key"
_PLAIN = "|ktest|fail|a plain service's LAUNCH or APPS was not refused ERR ACCESS by the manager"
_NOBAD = "|ktest|fail|an unknown request on a service's boot channel was not answered ERR BAD_REQUEST"
_DESK = "|ktest|fail|LAUNCH from the vouched desktop was not answered as the contract says"
_REG = "|ktest|fail|the vouched session was not given the registry of /SYSTEM/APPS"
_LAUNCH = "|ktest|fail|a LAUNCH of the vouched session was not answered as the contract states"
_REFUSED = "|ktest|fail|an application was not refused every request on its boot channel"
_MORE = "|ktest|fail|an application holds more than its boot channel"
_NOJOB = "|ktest|fail|an application is not in a job of its own under the session's job"
_SJANS = "|ktest|fail|END_SESSION or the LAUNCH after it was not answered as the contract states"
_LKALIVE = "|ktest|fail|an application of the signed-out session is still alive"
_LKSTEPS = "|ktest|fail|the sign-in, a launch or the sign-out was not as the case states"
_JBUNIT = "|ktest|fail|a job's count does not hold its bound"
_JBNOT = "|ktest|fail|a job's processes are not bounded"
_LRANS = "|ktest|fail|a LAUNCH was not answered as the rate limit states"
_SGSES = "|ktest|fail|a LAUNCH or BEGIN_SESSION of the session was not answered as the gate states"
_SGDESK = "|ktest|fail|the desktop opened the gate, or the session's exit did not close it"
_SGEXIT = "|ktest|fail|an application or a job of the session outlived the session service"
_SRKEPT = "|ktest|fail|an application of the restarted session outlived it, or the new session could not launch"
_SRCRASH = "|ktest|fail|an application of the crashed session outlived it, or the session started again could not launch"
_RLLOAD = "|ktest|fail|a user store was not loaded on a read of its owner or an administrator"
_RLAUTH = "|ktest|fail|a user store was read without its owner's or an administrator's usable token"
_RLSLOT = "|ktest|fail|a refused read or a store no volume holds took a slot of the table"
_RLFULL = "|ktest|fail|a full table stood before a policy value or a loaded store"
_ORPHAN = "|ktest|fail|an application that exited left a process of its job behind"
_JOBLEFT = "|ktest|fail|a job was left of a launch that failed or of an application that exited"
_APP_KEPT = "|ktest|fail|the manager kept a handle of a launch that failed or of an application that exited"
_NOLIST = "|ktest|fail|LIST request failed"
_CLAUNCH = "|ktest|fail|a LAUNCH of the connection case was not answered as the contract states"
_CHAND = "|ktest|fail|an application holds another number of handles than its grants give"
_CKEPT = "|ktest|fail|the manager kept a handle of a CONNECT it refused or of an application that exited"
EXPECT = {
    "M262": {"TST-M3-FAT32-FAULT-CREATE": ["exit 37", "|writes=8|", "|filled=8|", "|second_names=1|", _NAMES],
             "TST-M3-FAT32-FAULT-ONE-CREATE": ["exit 37", "|writes=8|", "|filled=8|", "|second_names=1|", _NAMES],
             "TST-M3-FAT32-FAULT-CREATE-COPIES": ["exit 37", "|calls=8|", "|second_names=1|", _NAMES]},
    "M265": {"TST-M3-FAT32-FAULT-ONE-CREATE": ["exit 37", "|writes=8|", "|filled=8|", "|second_free=1|", _FREE],
             "TST-M3-FAT32-FAULT-CREATE-COPIES": ["exit 37", "|calls=8|", "|second_free=1|", _FREE]},
    "M268": {"TST-M3-FAT32-FAULT-CREATE": ["exit 37", "|writes=8|", "|filled=8|", "|second_names=1|", "|second_longer=4|", _NAMES],
             "TST-M3-FAT32-FAULT-ONE-CREATE": ["exit 37", "|writes=8|", "|filled=8|", "|second_names=1|", "|second_longer=4|", _NAMES],
             "TST-M3-FAT32-FAULT-CREATE-COPIES": ["exit 37", "|calls=8|", "|second_names=1|", "|second_longer=4|", "|second_links=4|", _NAMES]},
    "M219": {"TST-M3-FAT32-FAULT-CREATE-COPIES": ["exit 37", "|calls=8|", "|second_shorter=2|", "|second_links=2|", _NAMES]},
    "M261": {"TST-M3-FAT32-FAULT-CREATE-COPIES": ["exit 37", "|calls=8|", "|second_names=1|", _NAMES]},
    # WP-106: the boot sectors a mutant of the mount's bounds lets through are among the last ten
    # sector lines, inside the kept window; M271's panic is shown by the line printed before it.
    "M270": {"TST-M3-FAT32-BPB": ["exit 37", "|refused=23|", "|accepted=10|", "|wrong=3|",
                                  _BPB + "mul_wrap|clusters=131008|data_start=64|mount=1",
                                  _BPB + "add_wrap|clusters=131056|data_start=16|mount=1",
                                  _BPB + "zero_start|clusters=131072|data_start=0|mount=1", _JUDGED]},
    "M271": {"TST-M3-FAT32-BPB": ["exit 35", _BPB + "fatsz16|refused=K_E_FS_BAD_BPB|mount=1"]},
    "M272": {"TST-M3-FAT32-BPB": ["exit 37", "|refused=24|", "|accepted=9|", "|wrong=2|",
                                  _BPB + "over_max|clusters=268435446|data_start=2097184|mount=1",
                                  _BPB + "too_many|clusters=2147483615|data_start=2147483680|mount=1", _JUDGED]},
    "M273": {"TST-M3-FAT32-BPB": ["exit 37", "|refused=25|", "|accepted=8|", "|wrong=1|",
                                  _BPB + "fat_small|clusters=129023|data_start=2048|mount=1", _JUDGED]},
    "M274": {"TST-M3-FAT32-BPB": ["exit 37", "|mount_same=30",
                                  _BPB + "spc8|clusters=65525|data_start=2080|mount=0",
                                  _BPB + "big_fat|clusters=65525|data_start=16777248|mount=0",
                                  _BPB + "max_ok|clusters=268435445|data_start=2097184|mount=0",
                                  "|ktest|fail|the mount did not answer a boot sector as its validation does"]},
    "M275": {"TST-M3-FAT32-BPB": ["exit 37", "|refused=27|", "|accepted=6|", "|wrong=1|",
                                  _BPB + "big_fat|refused=K_E_FS_BAD_BPB|mount=1", _JUDGED]},
    # WP-147: the made-up entry's one line; the failure is the kernel's own.
    "M276": {"TST-M3-FAT32-BAD-FIRST": ["exit 37", "|one_writes=5|", "|one_empty=0|", "|one_link=512|",
                                        "|one_link_writes=2|", "|hello_ok=0|", "|one_full=K_E_FS_DISK_FULL|", _UNREFUSED]},
    "M277": {"TST-M3-FAT32-BAD-FIRST": ["exit 37", "|past_end_empty=0|", "|far_empty=0|", _UNREFUSED]},
    "M278": {"TST-M3-FAT32-BAD-FIRST": ["exit 37", "|past_end_empty=0|", _UNREFUSED]},
    "M279": {"TST-M3-FAT32-BAD-FIRST": ["exit 37", "|last_empty=K_E_FS_CORRUPT|", _LAST]},
    "M280": {"TST-M3-FAT32-BAD-FIRST": ["exit 37", "|one_past=K_E_FS_RANGE|", _PAST]},
    # WP-149: the case's one line; the failure is the kernel's own.
    "M281": {"TST-M3-VMO-MAP-RIGHTS": ["exit 37", "|write_noread=mapped|", "|leak=1|", _K3]},
    # WP-107: the live balance's one line; every token stays: the body's six, the 20 replays' and
    # the second client's two (its request's and that of the replay whose reply cannot be written).
    "M323": {"TST-M4-CONFIG-RETRY": ["exit 37", "|body_grew=6|", "|replays_grew=20|", "|unwritable_grew=2|", _KEPT]},
    # WP-156: the case's one line: the three client ends stay with the manager and config keeps
    # their three slots.
    "M324": {"TST-M4-SVC-CONNECT-NOREAD": ["exit 37", "|mgr_grew=3|", "|cfg_grew=3|", _HELD]},
    # WP-157: the case's one line. M325: the two refused writes leave their stores (EXPORT finds
    # both). M326: the eight subscribers take the eight slots, so the user's own SET is refused.
    # M327: the administrator's SET on the store the user was refused is refused too.
    "M325": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|other_export=OK|", "|import_export=OK|", _LEFT]},
    "M327": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|admin_set=ERR ACCESS|", _ADMIN]},
    # The review round, the case's second line. M328: the user's SET on the loaded store is
    # applied (version 2) and EXPORT no longer lists the administrator's value. M329: the
    # subscriber to user/0 is accepted. M330: user/10000 is a store that is not loaded. M331: the
    # ninth store is refused as if the administrator had no right.
    "M328": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|loaded_other=OK 2|", "|loaded_kept=0|", _LOADED]},
    "M329": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|sub_zero=ERR ACCESS|", _NONAME]},
    "M330": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|sub_big=ERR ACCESS|", _NONAME]},
    "M331": {"TST-M4-CONFIG-STORE-AUTHZ": ["exit 37", "|full_set=ERR ACCESS|", _FULLTAB]},
    # WP-108: the case's one line. M332: client B, in A's slot, sees A's connection as its own
    # and finds A's port taken (it reads A's datagram too, when the echo has come: in the line,
    # not declared, as no expectation rests on an echo). M333: the port of the client that
    # closed while idle stays taken. M334: A's socket is gone but its connection is B's. M335:
    # C's close resets the connection B opened.
    "M332": {"TST-M4-NET-CLIENT-DROP": ["exit 37", "|tcp_a=OK state=ESTABLISHED|", "|reopen=ERR EXISTS|", _USED]},
    "M333": {"TST-M4-NET-CLIENT-DROP": ["exit 37", "|idle_reopen=ERR EXISTS|", _IDLE]},
    "M334": {"TST-M4-NET-CLIENT-DROP": ["exit 37", "|tcp_a=OK state=ESTABLISHED|", _USED]},
    "M335": {"TST-M4-NET-CLIENT-DROP": ["exit 37", "|tcp_b=ERR CLOSED|", _OTHER]},
    # WP-158: the case's two lines. M336: X's eight subscriptions of device all stand, with its
    # one of policy, and Y is refused. M337: neither X's nor Z's subscriptions go with their
    # client. M338: the session subscriber is accepted and hears the key. M339: Z's subscription
    # stays (the reply-failure path) while X's went. M340: X's subscriptions stay (the idle
    # path) while Z's end, on the other path, is closed. M341: X's subscription of the first
    # store goes and that of policy stays. Where two would share their changed fields, each
    # names one that holds, with its pinned value.
    "M336": {"TST-M4-CONFIG-SUBS": ["exit 37", "|x_grew=9|", "|y_sub=ERR FULL|", _MANY]},
    "M337": {"TST-M4-CONFIG-SUBS": ["exit 37", "|x_gone=0|", "|z_gone=0|", "|z_end_closed=0|", _SUBSTAY]},
    "M338": {"TST-M4-CONFIG-SUBS": ["exit 37", "|sess_sub=OK|", "|sess_heard=CHANGED session subs.s 1|", _SESS]},
    "M339": {"TST-M4-CONFIG-SUBS": ["exit 37", "|x_gone=1|", "|z_gone=0|", "|z_end_closed=0|", _ZSTAY]},
    "M340": {"TST-M4-CONFIG-SUBS": ["exit 37", "|x_gone=0|", "|x_end_closed=0|", "|z_end_closed=1|", _SUBSTAY]},
    "M341": {"TST-M4-CONFIG-SUBS": ["exit 37", "|x_gone=0|", "|x_pol_closed=0|", "|x_end_closed=1|", _SUBSTAY]},
    # WP-101: the case's one line; each lab service's exit code is what came back (0x51: the
    # first reply was another than the expected one; 0x61: no reply to the first request).
    # M342: the two plain services are answered as the vouched are. M343: the unknown request
    # gets no reply. M344: the desktop's LAUNCH is refused.
    "M342": {"TST-M6-LAUNCH-DENIED": ["exit 37", "|plain_launch=0x51|", "|plain_apps=0x51|", _PLAIN]},
    "M343": {"TST-M6-LAUNCH-DENIED": ["exit 37", "|unknown=0x61|", _NOBAD]},
    "M344": {"TST-M6-LAUNCH-DENIED": ["exit 37", "|desktop_launch=0x51|", _DESK]},
    # M345: the session is answered `OK clock notes other`, another reply than the expected one.
    "M345": {"TST-M6-LAUNCH-DENIED": ["exit 37", "|session_apps=0x51|", _REG]},
    # WP-161: the case's one line (kept as the local run of 2026-11-19 printed it). M346: the
    # eight share the manager's own job and the orphan's child lives. M347: two handles each. M348: the child lives, in a ninth job. M349: the ninth is
    # started as #12 (0x0c). M350: step 3 is answered #1 while clock#1 runs. M351: it is answered
    # #100 (0x64). M352, M354: the manager's count above 25 (v1.17: the session's job). M353, M356: jobs left. M355: the
    # request with two handles closes each channel, so four requests of each are not refused
    # (four handles more each). M357: none of the six is.
    "M346": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x40|", "|in_session=0|parents=1|jobs=1|live_jobs=9|orphans=1|", _NOJOB]},
    "M347": {"TST-M6-APP-SPAWN": ["exit 37", "|apps=8|waiting=8|handles=16|under_root=0|", _MORE]},
    "M348": {"TST-M6-APP-SPAWN": ["exit 37", "|in_session=8|parents=1|jobs=8|live_jobs=10|orphans=1|", _ORPHAN]},
    "M349": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x590c|apps=0|", _LAUNCH]},
    "M350": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x5301|apps=0|", _LAUNCH]},
    "M351": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x5364|apps=0|", _LAUNCH]},
    "M352": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=9|orphans=0|mgr_handles=27|", _APP_KEPT]},
    "M353": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=11|orphans=0|mgr_handles=27|", _JOBLEFT]},
    "M354": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=9|orphans=0|mgr_handles=33|", _APP_KEPT]},
    "M355": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x40|apps=8|waiting=0|handles=40|", _REFUSED]},
    "M356": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=110|orphans=0|mgr_handles=126|", _JOBLEFT]},
    "M357": {"TST-M6-APP-SPAWN": ["exit 37", "|session=0x40|apps=8|waiting=0|handles=56|", _REFUSED]},
    # The review round's four. M358: the manager is gone after the closer's close, so the test
    # kernel's LIST has no answer. M359: its end of that channel stays. M360: the closer's place
    # went to a clock, so its process and its job stay. M361: sixteen handles stay.
    "M358": {"TST-M6-APP-SPAWN": ["exit 37", "|ktest|app_spawn|list_error=", _NOLIST]},
    "M359": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=9|orphans=0|mgr_handles=26|", _APP_KEPT]},
    "M360": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=10|orphans=0|mgr_handles=27|", _JOBLEFT]},
    "M361": {"TST-M6-APP-SPAWN": ["exit 37", "|live_jobs=9|orphans=0|mgr_handles=41|", _APP_KEPT]},
    # WP-162: TST-M6-APP-CONNECT-DENIED (kept as the local run of 2026-11-20 printed it, after
    # the review round). M140, M378, M382 and M383 leave the test kernel's line as it is: the
    # case fails on its markers, the names the services hear (M140), the applications' traces
    # (M378: `net` answered ERR UNKNOWN and netonly granted config; M382: both granted config
    # again; M383: both refused display, netonly granted config). M142: connx's CONNECT session
    # reaches the launcher, which reads it as the reply to its next LAUNCH. M379, M380, M381:
    # more connections than the grants give (one more each, one more in all, every one). M384:
    # the client end `stuck` could not take stays in the manager.
    "M140": {"TST-M6-APP-CONNECT-DENIED": ["missing markers ['|text=svc|connect|app:connx#1', '|text=svc|connect|app:both#2', '|text=svc|connect|app:stuck#4', '|text=svc|connect|app:conn#8']"]},
    "M142": {"TST-M6-APP-CONNECT-DENIED": ["exit 37", "|session=0x5300|apps=0|", _CLAUNCH]},
    "M378": {"TST-M6-APP-CONNECT-DENIED": ["missing markers ['|text=app:connx#1|net=ERR ACCESS|session=ERR ACCESS|config=OK|ping=OK served|again=ERR LIMIT', '|text=app:netonly#3|config=ERR ACCESS'"]},
    "M379": {"TST-M6-APP-CONNECT-DENIED": ["exit 37", "|waiting=5|handles=12|mgr_handles=20|", _CHAND]},
    "M380": {"TST-M6-APP-CONNECT-DENIED": ["exit 37", "|waiting=5|handles=10|mgr_handles=20|", _CHAND]},
    "M381": {"TST-M6-APP-CONNECT-DENIED": ["exit 37", "|waiting=5|handles=15|mgr_handles=20|", _CHAND]},
    "M382": {"TST-M6-APP-CONNECT-DENIED": ["missing markers ['|text=app:both#2|config=OK|display=OK|again=ERR LIMIT']"]},
    "M383": {"TST-M6-APP-CONNECT-DENIED": ["missing markers ['|text=app:both#2|config=OK|display=OK|again=ERR LIMIT', '|text=app:netonly#3|config=ERR ACCESS'"]},
    "M384": {"TST-M6-APP-CONNECT-DENIED": ["exit 37", "|handles=9|mgr_handles=21|", _CKEPT]},
    # WP-102: TST-M6-SESSION-JOB (kept as the local run of 2026-11-20 printed it, after the
    # review round). The session's step k that saw another reply is 0x5k00. M141: the ended
    # session's applications run on, so END_SESSION again is not ENDED 0. M385: the same, the
    # applications' jobs under the root job (and in TST-M6-APP-SPAWN the eight there). M386:
    # the desktop and `sessions` end the session (0x51 each) before the session does. M387: the
    # LAUNCH after END_SESSION fails. M392: `sessions` ends it. M393: each is refused and ends it
    # all the same. M394: ENDED 2 where none is left. M395: a session job per LAUNCH (and in
    # TST-M6-APP-SPAWN eight parents).
    "M141": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5400|", "|nest=1|idle=1|under_root=0|in_session=1|live_jobs=3|", _SJANS]},
    "M385": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5400|", "|nest=1|idle=1|under_root=1|in_session=0|", _SJANS],
             "TST-M6-APP-SPAWN": ["exit 37", "|under_root=8|in_session=0|parents=1|", _NOJOB]},
    "M386": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5300|desktop=0x51|sessions=0x51|", _SJANS]},
    "M387": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5500|desktop=0x40|sessions=0x40|", _SJANS]},
    "M392": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5300|desktop=0x40|sessions=0x51|", _SJANS]},
    "M393": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5300|desktop=0x40|sessions=0x40|", _SJANS]},
    "M394": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5400|desktop=0x40|sessions=0x40|stay=0|", _SJANS]},
    "M395": {"TST-M6-SESSION-JOB": ["exit 37", "|session=0x5400|", "|nest=1|idle=1|under_root=0|in_session=1|live_jobs=4|", _SJANS],
             "TST-M6-APP-SPAWN": ["exit 37", "|in_session=8|parents=8|", _NOJOB]},
    # WP-167: TST-M6-LOGOUT-KILLS (kept as the local run of 2026-11-20 printed it). M388: the
    # signed-out session's three processes, its three jobs and the manager's seven handles stay.
    # M389: the session traces apps=0. M396: the answer is taken for a CONNECT's and nothing is
    # traced.
    "M388": {"TST-M6-LOGOUT-KILLS": ["exit 37", "|deaf=1|nest=1|idle=1|jobs=3|mgr_handles=7|", _LKALIVE]},
    "M389": {"TST-M6-LOGOUT-KILLS": ["forbidden present ['|text=session|jobs=ended|apps=0']"]},
    "M396": {"TST-M6-LOGOUT-KILLS": ["missing markers ['|text=session|jobs=ended|apps=2']; forbidden present []"]},
    # WP-164: TST-M6-JOB-BOUND (kept as the local run of 2026-11-21 printed it). M397: the count's
    # own check gives 40 places of 40. M398: every process counted in the root, hog's job counts
    # none while 65 live. M399: a place given back stays taken. M400: 33 places.
    "M397": {"TST-M6-JOB-BOUND": ["exit 37", "|unit|taken=40|refused=0|", _JBUNIT]},
    "M398": {"TST-M6-JOB-BOUND": ["exit 37", "|hog_live=65|hog_count=0|", _JBNOT]},
    "M399": {"TST-M6-JOB-BOUND": ["exit 37", "|again=0|counted=32|back=32|", _JBUNIT]},
    "M400": {"TST-M6-JOB-BOUND": ["exit 37", "|unit|taken=33|", _JBUNIT]},
    "M401": {"TST-M6-LAUNCH-RATE": ["exit 37", "|session=0x5711|", _LRANS]},
    "M402": {"TST-M6-LAUNCH-RATE": ["exit 37", "|session=0x5400|", _LRANS]},
    "M403": {"TST-M6-LAUNCH-RATE": ["exit 37", "|session=0x5a00|", _LRANS]},
    "M404": {"TST-M6-LAUNCH-RATE": ["exit 37", "|session=0x5900|", _LRANS]},
    "M405": {"TST-M6-LAUNCH-RATE": ["exit 37", "|session=0x5710|", _LRANS]},
    "M406": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x5100|desktop=0x5200|", _SGSES]},
    "M407": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x0|desktop=0x5100|", _SGDESK]},
    "M408": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x5600|", _SGSES]},
    "M409": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x0|desktop=0x5200|", _SGDESK]},
    "M411": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x5900|", _SGSES]},
    "M412": {"TST-M6-SESSION-GATE": ["exit 37", "|session=0x5300|", _SGSES]},
    "M415": {"TST-M6-SESSION-GATE": ["exit 37", "|stays=1|waiting=1|live_jobs=2|mgr_handles=4|", _SGEXIT]},
    "M416": {"TST-M6-SESSION-GATE": ["exit 37", "|stays=0|waiting=0|live_jobs=1|mgr_handles=1|", _SGEXIT]},
    # WP-173 (services.md v1.20): a RESTART's exit (0x40, the manager stopping), a crash (killed while
    # ready, started again on failure) and a STOP end the job too, and close the gate.
    "M417": {"TST-M6-SESSION-RESTART": ["exit 37", "|exit=0x40|restarts=1|held=1|stays=2|new_job=0|live_jobs=3|mgr_handles=7|", _SRKEPT]},
    "M418": {"TST-M6-SESSION-RESTART": ["exit 37", "|exit=0x5100|restarts=3|held=0|stays=0|new_job=0|live_jobs=0|mgr_handles=0|", _SRKEPT]},
    "M419": {"TST-M6-SESSION-RESTART": ["exit 37", "|exit=0x20000|restarts=2|held=1|stays=2|new_job=0|live_jobs=3|mgr_handles=7|", _SRCRASH]},
    "M420": {"TST-M6-SESSION-RESTART": ["exit 37", "|exit=0xe4|restarts=3|held=0|stays=0|new_job=0|live_jobs=0|mgr_handles=0|", _SRKEPT]},
    "M421": {"TST-M6-SESSION-RESTART": ["exit 37", "|exit=0xe4|restarts=3|held=0|stays=4|new_job=0|live_jobs=5|mgr_handles=13|", _SRKEPT]},
    # WP-112 (config.md v1.6): a user store is read for its owner's or an administrator's usable token
    # alone, loaded on that read; a refused read and a store no volume holds take no slot.
    "M422": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|ktest|config_read_load|bare=OK 1 mine|",
                      "|other=OK 1 hidden|other_export=OK;lab.read 1 hidden|absent=6|filled=5|", _RLAUTH]},
    "M423": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|admin=ERR NOT_FOUND|", "|full_set=OK 1|full_read=ERR NOT_FOUND|", _RLLOAD]},
    "M424": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|revoked=OK 2 new|revoked_export=OK;lab.read 2 new|",
                                         "|admin_expired=OK 1 theirs|", "|admin_revoked=OK 1 theirs|", _RLAUTH]},
    "M425": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|absent=6|filled=0|", _RLSLOT]},
    "M426": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|resolve=ERR NOT_FOUND|", _RLLOAD]},
    "M427": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|bare=ERR NOT_FOUND|resolve=OK user 1 mine|bare_loaded=OK 1 mine|",
                      "|other_loaded=OK 1 theirs|other_loaded_export=OK;lab.read 1 theirs|other=ERR NOT_FOUND|", _RLAUTH]},
    "M428": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|absent=6|filled=6|full_set=ERR INVALID|full_read=ERR NOT_FOUND|", _RLSLOT]},
    "M429": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|other_loaded=ERR NOT_FOUND|other_loaded_export=OK;lab.read 1 theirs|", _RLAUTH]},
    # WP-112's review round: with the table full, minted tokens, a write after a read-load, SUBSCRIBE.
    "M430": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|admin_expired=OK 1 theirs|", "|admin_revoked=OK 1 theirs|", _RLAUTH]},
    "M431": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|refused_full=ERR INVALID|bare_full=ERR INVALID|", _RLAUTH]},
    "M432": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|cw=OK 1 theirs|", _RLAUTH]},
    "M433": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|grp=OK 1 theirs|", _RLAUTH]},
    "M434": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|loaded_full=ERR INVALID|resolve_full=ERR INVALID|", _RLFULL]},
    "M435": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|policy_full=ERR INVALID|", _RLFULL]},
    # the guest passes: the host check finds the write in slot A, generation 1, and no slot B
    "M436": {"TST-M4-CONFIG-READ-LOAD": ["host checks", "/SYSTEM/CFGU1001.B NAWAH-CFG 1 2  -> 2",
                      "/SYSTEM/CFGU1001.A lab.read 1 mine\\n -> 1"]},
    "M437": {"TST-M4-CONFIG-READ-LOAD": ["exit 37", "|sub_loaded=OK|", _RLAUTH]},
    "M410": {"TST-M6-LOGOUT-KILLS": ["exit 37", "|launched=ERR NO_SESSION,ERR NO_SESSION|", _LKSTEPS]},
    "M413": {"TST-M6-LOGOUT-KILLS": ["exit 37", "|gate|before=OK app:deaf#1|", _LKALIVE]},
    "M414": {"TST-M6-LOGOUT-KILLS": ["exit 37", "|gate|before=ERR NO_SESSION|after=OK app:deaf#3|", _LKSTEPS]},
}


def expect_errors():
    """EXPECT checked statically: every mutant registered, every killer among that mutant's
    declared killers, every substring list non-empty and without an empty string."""
    by_id = {m[0]: m for m in MUTANTS}
    errs = []
    for mid, per in EXPECT.items():
        if mid not in by_id:
            errs.append(f"EXPECT names {mid}, which is not a registered mutant")
            continue
        for k, subs in per.items():
            if k not in by_id[mid][4]:
                errs.append(f"EXPECT {mid} names {k}, which is not among {mid}'s declared killers")
            if not subs or any(not s for s in subs):
                errs.append(f"EXPECT {mid} {k}: empty substring list or empty substring")
    return errs


# The test kernel's own lines only (red team B1): a ring-3 program's SYS_TRACE line
# `OSX|<id>|user|trace|...|text=...` may carry `|ktest|fail|...` and field strings in its text.
KTEST_LINE = re.compile(r"^OSX\|[0-9a-f]+\|ktest\|")
INVALID_MISS = "the mutant is invalid, so its declared kill was not shown"


def kill_evidence(out: str, env, tid, target, host: bool):
    """What a FAIL of `tid` leaves to judge the kill by, read before the scratch is emptied: the
    driver's reason and run id from its verdict line, and (guest cases) the test kernel's lines of
    each boot of that run (serial-N.log for a multi-phase case, serial.log otherwise). A missing
    log gives no lines, never an error."""
    if host:
        m = re.search(rf"^{re.escape(tid)}: FAIL run=(\S+)", out, re.M)
        return {"reason": "host: the runner reported failing tests and the case passes on the clean checkout",
                "run": m.group(1) if m else "", "lines": []}
    hits = re.findall(rf"^{re.escape(tid)} {re.escape(target)}: FAIL \((.*)\) run=(\S+)\s*$", out, re.M)
    reason, run = hits[-1] if hits else ("", "")
    lines = []
    scratch = env.get("NAWAH_SCRATCH_EVIDENCE")
    if scratch and run and "/" not in run and run not in (".", ".."):
        d = Path(scratch) / run
        boots = sorted(d.glob("serial-*.log"), key=lambda p: (len(p.name), p.name)) or [d / "serial.log"]
        for p in boots:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            kept = [l[:KILL_LINE_CHARS] for l in (x.rstrip("\r") for x in text.splitlines()) if KTEST_LINE.match(l)]
            lines += kept[-KILL_LINES:]
    return {"reason": reason[:KILL_REASON_CHARS], "run": run, "lines": lines}


def expected_misses(mid, results):
    """The declared expectations of `mid` that its kills do not show (killer and substring)."""
    missed = []
    for k, subs in EXPECT.get(mid, {}).items():
        ev = KILLS.get(k)
        if results.get(k) != "FAIL" or ev is None:
            missed.append(f"{k}: did not FAIL ({results.get(k, 'not run')})")
            continue
        hay = ev["reason"] + "\n" + "\n".join(ev["lines"])
        missed += [f"{k}: {s!r} not in its reason or kept lines" for s in subs if s not in hay]
    return missed


def run_killers(wt: Path, env, target, killers, early_exit=False):
    """Returns (killed_by: list, results: {test_id: PASS|FAIL|SKIPPED|ERROR}). Every case runs
    through its suite entry (the strong oracle); a missing artifact (exit 20) is SKIPPED and a
    lab failure (QEMU died, LAB_ERROR) is ERROR — neither is a kill. With early_exit the run
    stops at the first FAIL (one kill is enough): the fairness sweep over ~140 cases need not
    finish once a mutant is caught, which is most of a surviving-mutant run's cost."""
    results = {}
    for tid in killers:
        suite = suite_of(target, tid)
        host_suite = None
        if suite is None:
            # A host case (libui's unit tests, the text conformance suites, the tooling checks)
            # runs on the worktree's files through the clean driver; it knows its suite.
            host_suite = host_suite_of(wt, tid)
            if host_suite is None:
                results[tid] = "SKIPPED"
                continue
            r = sh(PYPROJ + ["test", "--target", "host", "--suite", host_suite, "--only", tid], wt, env)
        else:
            r = sh(PYPROJ + ["test", "--target", target, "--suite", suite, "--only", tid], wt, env)
        if r.returncode == 0:
            results[tid] = "PASS"
        elif host_suite is not None and not (runner_reported_failures(r.stdout, env) and passes_clean(env, host_suite, tid)):
            # Not caused by the mutant (see RUNNER_FAILED): never a kill.
            results[tid] = "ERROR"
        elif r.returncode == 20 or "no artifact" in r.stdout:
            results[tid] = "SKIPPED"
        elif "LAB_ERROR" in r.stdout:
            # The emulator died twice: no verdict on the mutant from this case (never a kill).
            results[tid] = "ERROR"
        elif host_suite is None and not (r.returncode == 1 and re.search(
                rf"^{re.escape(tid)} {re.escape(target)}: FAIL\b.* run=\S+", r.stdout, re.M)):
            # A guest kill is project.py's own FAIL verdict for this case (rc 1); an internal error
            # (rc 60: no QEMU or OVMF, unknown case ids) is never a kill (WP-90 audit).
            results[tid] = "ERROR"
        else:
            results[tid] = "FAIL"
            KILLS[tid] = kill_evidence(r.stdout, env, tid, target, host_suite is not None)
            if early_exit:
                break
    return [t for t, v in results.items() if v == "FAIL"], results


def all_cases(target):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    ids = ["TST-M1-BOOT"]
    for cases in t["suites"].values():
        ids += [c["id"] for c in cases if c["id"] not in ("TST-M1-BOOT",)]
    return ids


def harness_env(base, wt: Path, scratch: Path):
    """The killers' environment: the worktree as NAWAH_ROOT, scratch evidence, the per-case QEMU
    timeout, and no CARGO_TARGET_DIR, so the worktree and the clean checkout each build in their
    own target/ (a shared one let the clean run reuse a mutated build, WP-90), nor NAWAH_GATE_SHARDS,
    which would turn a killer's own run of a gate into a merge (L-023, WP-152)."""
    env = {k: v for k, v in base.items() if k not in ("CARGO_TARGET_DIR", GATE_SHARDS_ENV)}
    env.update(NAWAH_ROOT=str(wt), NAWAH_SCRATCH_EVIDENCE=str(scratch), NAWAH_QEMU_TIMEOUT_S=str(MUTANT_CASE_TIMEOUT_S))
    return env


def gate_verdict(report) -> bool:
    """The gate's verdict (WP-90): kill ratio >= THRESHOLD over a non-empty set of valid mutants,
    no surviving SECURITY mutant, and no invalid SECURITY mutant (an anchor that no longer matches
    or a mutant that does not build would otherwise leave the SECURITY rule silently)."""
    report["surviving_security"] = [m for m in report["survived"] if security_of(m)]
    report["invalid_security"] = [m for m in report["invalid"] if security_of(m)]
    return bool(report["ratio"] >= THRESHOLD and report["valid"] and not report["surviving_security"]
                and not report["invalid_security"] and not report.get("expected_missed")
                and not report.get("expect_errors"))


def parse_shard(spec: str):
    """`k/N` as (k, N): two plain decimal numbers with 1 <= k <= N; anything else is a ValueError."""
    m = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", spec)
    if not m or int(m.group(1)) > int(m.group(2)):
        raise ValueError(f"--shard {spec!r} is not k/N with 1 <= k <= N")
    return int(m.group(1)), int(m.group(2))


def shard_arg(spec: str):
    try:
        return parse_shard(spec)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(str(ex))


def in_shard(mid: str, k: int, n: int) -> bool:
    """Whether mutant `mid` is in shard k of n (WP-98): a rule on the id alone, the same on every
    runner and stable as the list grows."""
    return int(mid[1:]) % n == k - 1


def selection(stage=None, only=None, shard=None) -> list:
    """The MUTANTS entries a run takes, in their order: of `stage`, of `only` (a list of ids) and
    of `shard` ((k, N)), each when given."""
    return [m for m in MUTANTS if (not only or m[0] in only) and (not stage or stage_of(m[0]) == stage)
            and (shard is None or in_shard(m[0], *shard))]


def shard_report(report_rel: str, k: int, n: int) -> str:
    """Where shard k of n writes its report: beside the gate's report, in <stem>.shards/."""
    p = Path(report_rel)
    return (p.parent / f"{p.stem}.shards" / f"shard-{k}-of-{n}.json").as_posix()


def run_identity() -> dict:
    """The run a shard report belongs to: the CI run id, attempt and sha when GITHUB_RUN_ID is set,
    else the checkout's git HEAD (an empty value is no identity; the merge refuses it)."""
    env = os.environ
    if env.get("GITHUB_RUN_ID"):
        return {"github_run_id": env.get("GITHUB_RUN_ID", ""), "github_run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
                "github_sha": env.get("GITHUB_SHA", "")}
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True)
    return {"git_head": r.stdout.strip() if r.returncode == 0 else ""}


def summarize(report) -> None:
    """A run's totals from its decided entries (a full run, a shard, or the union of the shards):
    counted from the entries, never taken from another report's totals."""
    # An invalid mutant (anchor gone, does not compile or build) with EXPECT never showed its
    # declared kill (red team B3): expected_missed on every path that marks it invalid, so a
    # non-SECURITY one cannot leave its expectation unjudged while the ratio passes.
    for m in report["mutants"]:
        if m["status"] == "invalid" and m["id"] in EXPECT and not m.get("expected_missed"):
            m["expected_missed"] = [INVALID_MISS]
            print(f"{m['id']}: expected_missed {INVALID_MISS}")
    valid = [m for m in report["mutants"] if m["status"] in ("killed", "survived")]
    killed = [m for m in valid if m["status"] == "killed"]
    ratio = len(killed) / len(valid) if valid else 0.0
    report.update(valid=len(valid), killed=len(killed), survived=[m["id"] for m in valid if m["status"] == "survived"],
                  declared_killers_missed=[m["id"] for m in report["mutants"] if m.get("declared_killers_missed")],
                  expected_missed=[m["id"] for m in report["mutants"] if m.get("expected_missed")],
                  invalid=[m["id"] for m in report["mutants"] if m["status"] == "invalid"], ratio=round(ratio, 4),
                  finished=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def print_entry(e) -> None:
    """A decided mutant's line, then its kept kill evidence and its missed expectations indented."""
    if e.get("status") == "invalid":
        print(f"{e.get('id')}: INVALID ({e.get('note', '')})")
    else:
        print(f"{e.get('id')}: {'killed by ' + ','.join(e['killed_by']) if e.get('killed_by') else 'SURVIVED'} [{e.get('seconds')}s] ({e.get('note', '')})")
        for k, ev in (e.get("kills") or {}).items():
            print(f"  {k}: {ev['reason']} run={ev['run']}")
            for line in ev["lines"]:
                print(f"    {line}")
    for m_ in e.get("expected_missed") or []:
        print(f"  expected_missed {m_}")


def verdict_line(report, verdict, rel, prefix="") -> str:
    v, k, errs = report["valid"], report["killed"], report.get("expect_errors")
    return (f"\n{prefix}{'OK' if verdict else 'FAIL'}: {k}/{v} valid mutants killed ({(k / v if v else 0.0):.1%}, threshold {THRESHOLD:.0%}); "
            f"survived={report['survived']}; surviving_security={report['surviving_security']}; invalid={report['invalid']}; "
            f"invalid_security={report['invalid_security']}; declared_killers_missed={report['declared_killers_missed']}; "
            f"expected_missed={report['expected_missed']}" + (f"; EXPECT errors: {errs}" if errs else "") + f"; report={rel}")


class MergeRefused(Exception):
    """A set of shard reports the merge does not judge; the message names why."""


def merge_shards(report_rel, n, stage=None, only=None, target="pc-qemu"):
    """The gate's report over the union of its n shard reports, summarized and judged by
    gate_verdict as a full run's is (WP-98): returns (report, verdict). Raises MergeRefused, judging
    nothing, unless the set is exactly the stage's mutants decided once by this very run: every one
    of the n reports there, each naming its own k/n, this run's identity and target and the rule's
    selection for it, holding only ids of that selection, none twice across the set, every one
    decided; and their union exactly the mutants of `stage` (and `only`). Valid and killed are
    counted over the union; no shard's ratio, list or verdict is taken."""
    me = run_identity()
    if not me or not all(me.values()):
        raise MergeRefused(f"the merging run has no run identity ({me})")
    want = [m[0] for m in selection(stage, only)]
    reports, entries, where = [], {}, {}
    for k in range(1, n + 1):
        rel = shard_report(report_rel, k, n)
        p = REPO / rel
        if not p.is_file():
            raise MergeRefused(f"shard {k}/{n} is missing ({rel})")
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            r = None
        if not (isinstance(r, dict) and isinstance(r.get("shard"), dict) and isinstance(r.get("mutants"), list)
                and all(isinstance(e, dict) for e in r["mutants"])):
            raise MergeRefused(f"{rel} is not a shard report")
        named = (r["shard"].get("k"), r["shard"].get("n"))
        if named != (k, n):
            raise MergeRefused(f"{rel} names shard {named[0]}/{named[1]}, not {k}/{n}")
        if r.get("run") != me:
            raise MergeRefused(f"shard {k}/{n} names run {r.get('run')}, not this run's {me}")
        if r.get("target") != target:
            raise MergeRefused(f"shard {k}/{n} names target {r.get('target')!r}, not {target!r}")
        sel = [m[0] for m in selection(stage, only, (k, n))]
        if r["shard"].get("selected") != sel:
            raise MergeRefused(f"shard {k}/{n} selected {r['shard'].get('selected')}, the rule selects {sel}")
        for e in r["mutants"]:
            mid = e.get("id")
            if mid not in sel:
                raise MergeRefused(f"{mid} in shard {k}/{n} is not in its selection")
            if mid in where:
                raise MergeRefused(f"{mid} is decided twice (shard {where[mid]}/{n} and shard {k}/{n})")
            where[mid], entries[mid] = k, e
        undecided = [mid for mid in sel if entries.get(mid, {}).get("status") not in DECIDED]
        if undecided:
            raise MergeRefused(f"shard {k}/{n} is truncated: {len(sel) - len(undecided)} of its {len(sel)} mutants decided (not: {undecided})")
        if r["shard"].get("complete") is not True:
            raise MergeRefused(f"shard {k}/{n} did not finish (its report never says complete)")
        reports.append((k, rel, r))
    if set(where) != set(want):
        raise MergeRefused(f"the shards' union is not the stage's mutants (missing {sorted(set(want) - set(where))}, "
                           f"extra {sorted(set(where) - set(want))})")
    merged = {"threshold": THRESHOLD, "target": target, "mutants": [entries[mid] for mid in want if mid in entries],
              "started": min(str(r.get("started", "")) for _, _, r in reports), "run": me,
              "merged": {"n": n, "rule": SHARD_RULE, "env": f"{GATE_SHARDS_ENV}={n}",
                         "shards": [{"k": k, "report": rel, "mutants": len(r["mutants"]), "started": r.get("started"),
                                     "finished": r.get("finished")} for k, rel, r in reports]}}
    errs = list(dict.fromkeys(expect_errors() + [str(e) for _, _, r in reports for e in (r.get("expect_errors") or [])]))
    if errs:
        merged["expect_errors"] = errs
    summarize(merged)
    verdict = gate_verdict(merged)
    return merged, verdict


def merge_main(a, raw: str) -> int:
    """NAWAH_GATE_SHARDS=N: the gate's command merges its N shard reports (WP-98). It runs no
    mutant and never falls back to a full run; a refusal prints its reason, no verdict line, and
    leaves no report (an older one is removed first)."""
    (REPO / a.report).unlink(missing_ok=True)
    try:
        if not re.fullmatch(r"[1-9][0-9]*", raw):
            raise MergeRefused(f"{GATE_SHARDS_ENV}={raw!r} is not a shard count (a whole number >= 1)")
        if a.shard or a.check:
            raise MergeRefused(f"{GATE_SHARDS_ENV} is set: a merge takes neither --shard nor --check")
        n = int(raw)
        print(f"merge of {n} shard reports ({GATE_SHARDS_ENV}={n}, rule {SHARD_RULE}) from {Path(shard_report(a.report, 1, n)).parent.as_posix()}/")
        report, verdict = merge_shards(a.report, n, a.stage, a.only.split(",") if a.only else None, a.target)
    except MergeRefused as ex:
        print(f"merge refused: {ex}; no verdict")
        return MERGE_REFUSED
    for sh_ in report["merged"]["shards"]:
        print(f"shard {sh_['k']}/{n}: {sh_['report']}, {sh_['mutants']} mutants, started {sh_['started']}, finished {sh_['finished']}")
    for e in report["mutants"]:
        print_entry(e)
    _write_report(a.report, report)
    print(verdict_line(report, verdict, a.report))
    return 0 if verdict else 1


def add_worktree(wt: Path) -> None:
    """The run's worktree of HEAD with every top-level tree but evidence/ (WP-130, RSK-038): no
    killer reads evidence/ (each writes to the scratch evidence), and a full checkout of it took
    11 GB on disk on 2026-11-15. The index of the worktree lists evidence/ as deleted; reset()
    looks at the trees a mutant may touch only."""
    subprocess.run(["git", "worktree", "add", "-q", "--detach", "--no-checkout", str(wt), "HEAD"], cwd=REPO, check=True)
    names = subprocess.run(["git", "ls-tree", "-z", "--name-only", "HEAD"], cwd=wt, check=True,
                           capture_output=True, text=True).stdout.split("\0")
    subprocess.run(["git", "checkout", "-q", "HEAD", "--"] + [n for n in names if n and n != "evidence"], cwd=wt, check=True)


def hold_lock(path: Path):
    """The run's lock, held until the file is closed or the process dies (the kernel releases a
    flock on SIGKILL too, when no cleanup of the run's own runs)."""
    f = open(path, "w")
    if fcntl is not None:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return f


def lock_held(path: Path) -> bool:
    """Whether a live run holds the lock at `path`; a missing lock file is no live run's. Without
    flock every lock reads held."""
    if fcntl is None:
        return True
    try:
        f = open(path, "rb")
    except OSError:
        return False
    with f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        return False


def remove_stale_worktrees() -> list:
    """At start, the leftovers of a run killed before its cleanup (WP-130, RSK-038): every linked
    worktree git lists for REPO at <TMP_ROOT>/nawah-mutants-*/<name>, whose run's lock no live run
    holds, is removed with its temporary directory (`git worktree remove --force` also drops the
    registration of one whose directory is gone, so no `git worktree prune` runs). Any other
    worktree stays."""
    out = subprocess.run(["git", "worktree", "list", "--porcelain"], cwd=REPO, capture_output=True, text=True).stdout
    paths = [Path(l[len("worktree "):]) for l in out.splitlines() if l.startswith("worktree ")][1:]
    root = Path(TMP_ROOT).resolve()
    removed = []
    for p in paths:
        tmp = p.parent
        if tmp.parent.resolve() != root or not tmp.name.startswith(PREFIX):
            continue
        if lock_held(tmp / "lock"):
            continue
        subprocess.run(["git", "worktree", "remove", "--force", str(p)], cwd=REPO, capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
        removed.append(p)
        print(f"removed the worktree of a stopped run: {p}")
    return removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="pc-qemu")
    ap.add_argument("--report", default="build/mutants-report.json")
    ap.add_argument("--only", help="comma-separated mutant ids")
    ap.add_argument("--stage", choices=list(STAGES), help="run only the mutants of one gate (M01-M29 = M2, M30-M49 = M3, M50-M81 = M4, M82-M129 = M5, M130.. = M6)")
    ap.add_argument("--check", action="store_true", help="apply/revert each patch and cargo check on the host target only")
    ap.add_argument("--shard", type=shard_arg, metavar="k/N", help="run shard k of N of the selected mutants (int(id[1:]) mod N == k-1) "
                    "and write the report to <report stem>.shards/shard-k-of-N.json; NAWAH_GATE_SHARDS=N merges the N reports (WP-98)")
    a = ap.parse_args()
    gate_shards = os.environ.get(GATE_SHARDS_ENV)
    if gate_shards is not None:
        return merge_main(a, gate_shards)
    only = a.only.split(",") if a.only else None
    mutants = selection(a.stage, only, a.shard)
    report_rel = shard_report(a.report, *a.shard) if a.shard else a.report
    prefix = f"shard {a.shard[0]}/{a.shard[1]}: " if a.shard else ""
    remove_stale_worktrees()
    tmp = Path(tempfile.mkdtemp(prefix=PREFIX, dir=TMP_ROOT))
    lock = hold_lock(tmp / "lock")
    wt = tmp / "wt"
    scratch = tmp / "scratch-evidence"
    report = {"threshold": THRESHOLD, "target": a.target, "mutants": [], "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if a.shard:
        # The shard's identity (WP-98): the merge refuses a report of another shard, selection or run.
        report["shard"] = {"k": a.shard[0], "n": a.shard[1], "rule": SHARD_RULE, "stage": a.stage, "only": only,
                           "selected": [m[0] for m in mutants]}
        report["run"] = run_identity()
        print(f"{prefix}{len(mutants)} mutants ({SHARD_RULE}) of run {report['run']}: {','.join(report['shard']['selected'])}")
    bad_expect = expect_errors()
    for e in bad_expect:
        print(e)
    if bad_expect:
        report["expect_errors"] = bad_expect
    try:
        scratch.mkdir()
        add_worktree(wt)
        env = harness_env(os.environ, wt, scratch)
        env.setdefault("RUSTUP_TOOLCHAIN", os.environ.get("RUSTUP_TOOLCHAIN", ""))
        if not env["RUSTUP_TOOLCHAIN"]:
            del env["RUSTUP_TOOLCHAIN"]
        for m in mutants:
            mid, rel, old, new, killers, note = m
            t0 = time.time()
            entry = {"id": mid, "file": rel, "note": note, "killers": killers, "security": security_of(mid)}
            reset(wt)
            try:
                apply(wt, m)
            except RuntimeError as ex:
                entry.update(status="invalid", reason=str(ex)); report["mutants"].append(entry); print(f"{mid}: INVALID ({ex})"); continue
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
                report["mutants"].append(entry)
                print(f"{mid}: {'compiles' if ok else 'DOES NOT COMPILE'} ({note})")
                continue
            benv = dict(env, NAWAH_BUILD_ID=mutant_build_id(mid), NAWAH_OUT=str(wt / "build" / a.target),
                        NAWAH_APPS_DIR=str(wt / "build" / a.target / "apps"))
            need_release = needs_release(a.target, killers)
            out_dir = wt / "build" / a.target

            def build_image():
                """The mutant's apps, test image and (when a killer boots it) release image. The
                images a previous mutant left are removed first (the harness's own outputs only),
                so a guest case never boots another mutant's kernel."""
                for name in ("NAWAH-KTEST.EFI", "NAWAH.EFI", "NAWAH-NEG.EFI", "build-id.txt"):
                    (out_dir / name).unlink(missing_ok=True)
                shutil.rmtree(out_dir / "apps", ignore_errors=True)
                (out_dir / "apps").mkdir(parents=True, exist_ok=True)
                steps = [app_step(n) for n in APPS] + [(KTEST_STEP, KTEST_OUT, "NAWAH-KTEST.EFI")]
                if need_release:
                    steps.append((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"))
                for step, out, name in steps:
                    r = sh(step, wt, benv, timeout=1800)
                    if r.returncode != 0:
                        entry["reason"] = r.stdout[-2000:]
                        return False
                    shutil.copy(wt / out, out_dir / name)
                (out_dir / "build-id.txt").write_text(benv["NAWAH_BUILD_ID"] + "\n")
                return True

            built = needs_image(a.target, rel, killers)
            entry["image_built"] = built
            if built and not build_image():
                entry.update(status="invalid", seconds=round(time.time() - t0, 1)); report["mutants"].append(entry)
                print(f"{mid}: INVALID (does not build) ({note})"); continue
            KILLS.clear()
            killed_by, results = run_killers(wt, env, a.target, killers)
            missed = expected_misses(mid, results)
            declared_miss = not killed_by
            if not killed_by and not built and not is_tooling(rel):
                # A source mutant its host killers missed: the sweep below boots its image.
                built = entry["image_built"] = build_image()
                if not built:
                    entry.update(status="invalid", results=results, seconds=round(time.time() - t0, 1)); report["mutants"].append(entry)
                    print(f"{mid}: INVALID (does not build) ({note})"); _write_report(report_rel, report); continue
            if not killed_by and built:
                # Be fair before declaring a survivor: build the remaining artifacts and run
                # everything the suites have.
                rest = [c for c in all_cases(a.target) if c not in killers]
                for step, out, name in ((RELEASE_STEP, RELEASE_OUT, "NAWAH.EFI"), (NEG_STEP, NEG_OUT, "NAWAH-NEG.EFI")):
                    if (wt / "build" / a.target / name).exists() and name == "NAWAH.EFI" and need_release:
                        continue
                    r = sh(step, wt, benv, timeout=1800)
                    if r.returncode == 0:
                        shutil.copy(wt / out, wt / "build" / a.target / name)
                more_killed, more = run_killers(wt, env, a.target, rest, early_exit=True)
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
                         seconds=round(time.time() - t0, 1), kills=dict(KILLS))
            if missed:
                entry["expected_missed"] = missed
            report["mutants"].append(entry)
            print_entry(entry)
            _write_report(report_rel, report)
    finally:
        try:
            if wt.exists():
                reset(wt)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=REPO)
            shutil.rmtree(tmp, ignore_errors=True)
            lock.close()
    summarize(report)
    if a.shard:
        # Written only here, after the finally block: a shard that raised in its last reset or was
        # stopped after its last mutant never says it finished, and the merge refuses it (WP-98).
        report["shard"]["complete"] = True
    _write_report(report_rel, report)
    if a.check:
        bad = [m["id"] for m in report["mutants"] if m["status"] == "invalid"]
        ok = not bad and not bad_expect
        print(f"\n{'OK' if ok else 'FAIL'}: {len(report['mutants']) - len(bad)}/{len(report['mutants'])} mutants apply and type-check" + (f"; invalid: {bad}" if bad else "")
              + (f"; EXPECT errors: {bad_expect}" if bad_expect else ""))
        return 0 if ok else 1
    verdict = gate_verdict(report)
    _write_report(report_rel, report)
    # A shard's line is its own mutants' (prefixed, so never project.py's PASS marker); the gate's
    # verdict over every shard is the merge's.
    print(verdict_line(report, verdict, report_rel, prefix))
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
