#!/usr/bin/env python3
"""TST-M2-MUTANTS (REQ-M2-014), TST-M3-MUTANTS (REQ-M3-010, WP-22) and TST-M4-MUTANTS
(REQ-M4-010, WP-31): seeded-defect mutation testing of the kernel and the system services
against the guest suites — M01..M29 cover arch/, mm/ and sync (M1/M2 suites); M30..M49 cover the
M3 modules (scheduler, objects, syscalls, ELF loader, MMIO window, TLB shootdown, SMP placement,
virtio-blk, FAT32, VFS) and are killed by M3 cases, including the host checks a case runs on the
disk image; M50 onwards cover the M4 modules (process/wait syscalls, tokens, device objects and
polling, system_info, dir_list, and the user-space services svcmgr, authd, configd, netd, sh)
and are killed by M4 cases, console sessions included (`--stage` selects one group).

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
     "            b\"auth\" => [self.authority, None],", "            b\"auth\" => [None, None],",
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
]

def stage_of(mid: str) -> str:
    """M01..M29 belong to the M2 gate (TST-M2-MUTANTS), M30..M49 to the M3 gate (TST-M3-MUTANTS),
    M50.. to the M4 gate (TST-M4-MUTANTS)."""
    n = int(mid[1:])
    return "M2" if n < 30 else ("M3" if n < 50 else "M4")

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
    return parts[1].replace("_", "-") if parts[0] == "user" else None


def suite_of(target, test_id):
    t = json.loads((REPO / "platform" / target / "target.json").read_text())
    for suite, cases in t["suites"].items():
        if any(c["id"] == test_id for c in cases):
            return suite
    return None


def run_killers(wt: Path, env, target, killers):
    """Returns (killed_by: list, results: {test_id: PASS|FAIL|SKIPPED|ERROR}). Every case runs
    through its suite entry (the strong oracle); a missing artifact (exit 20) is SKIPPED and a
    lab failure (QEMU died, LAB_ERROR) is ERROR — neither is a kill."""
    results = {}
    pyproj = ["python3", str(wt / "tools" / "project.py")]
    for tid in killers:
        suite = suite_of(target, tid)
        r = sh(pyproj + ["test", "--target", target, "--suite", suite, "--only", tid], wt, env)
        if r.returncode == 0:
            results[tid] = "PASS"
        elif r.returncode == 20 or "no artifact" in r.stdout:
            results[tid] = "SKIPPED"
        elif "LAB_ERROR" in r.stdout:
            # The emulator died twice: no verdict on the mutant from this case (never a kill).
            results[tid] = "ERROR"
        else:
            results[tid] = "FAIL"
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
    ap.add_argument("--stage", choices=["M2", "M3", "M4"], help="run only the mutants of one gate (M01-M29 = M2, M30-M49 = M3, M50.. = M4)")
    ap.add_argument("--check", action="store_true", help="apply/revert each patch and cargo check on the host target only")
    a = ap.parse_args()
    mutants = [m for m in MUTANTS if (not a.only or m[0] in a.only.split(",")) and (not a.stage or stage_of(m[0]) == a.stage)]
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
            benv = dict(env, NAWAH_BUILD_ID=f"mut{mid.lower()}", NAWAH_OUT=str(wt / "build" / a.target),
                        NAWAH_APPS_DIR=str(wt / "build" / a.target / "apps"))
            (wt / "build" / a.target / "apps").mkdir(parents=True, exist_ok=True)
            need_release = "TST-M1-BOOT" in killers
            build_ok = True
            steps = [app_step(n) for n in APPS] + [(KTEST_STEP, KTEST_OUT, "NAWAH-KTEST.EFI")]
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
