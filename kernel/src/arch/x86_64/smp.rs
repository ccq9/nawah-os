//! Application-processor bring-up (WP-20, ADR-0015). The boot CPU starts the others one at a
//! time with INIT, SIPI, SIPI and waits for each to report in, then keeps the table of CPUs
//! (APIC IDs, stacks, online mask) the rest of the kernel asks about.
//!
//! References (Intel SDM rev. 093, docs/sources.json S26): Vol. 3A §9.4.4 (MP initialization
//! example: INIT then 10 ms, SIPI then 200 µs, SIPI then 200 µs; the SIPI vector is the start
//! page number below 1 MiB), §10.8.5 (entering IA-32e mode: PAE, CR3, EFER.LME, CR0.PG), §11.6.1
//! (ICR); ACPI 6.5 §5.2.12 (MADT local APIC entries, S33).
//!
//! The trampoline page below 1 MiB holds position-independent 16-bit code and data only. After
//! enabling protection it jumps into 32-bit code **inside the kernel image**, which is
//! identity-mapped and executable; the low page is RAM and therefore RW+NX in the kernel's
//! tables, so no instruction may be fetched from it once paging is on. Absolute addresses (the
//! two far-jump targets) travel as data because a 64-bit PE cannot carry 32-bit absolute
//! relocations. The params block is read through ESI/RSI by the 32- and 64-bit stages.

use core::arch::global_asm;
use core::sync::atomic::{fence, AtomicU32, Ordering};

use super::acpi::Madt;
use super::{apic, context, irq, paging, pit};
use crate::cell::BootCell;
use crate::mm::vmm::{self, StackInfo};

pub use super::gdt::MAX_CPUS;

/// Candidate start pages (SIPI vector = page): 0x08000..0x8F000, below the PMM's 1 MiB floor.
const TRAMP_PAGE_FIRST: u8 = 0x08;
const TRAMP_PAGE_LAST: u8 = 0x8F;
/// Layout of the trampoline page (the assembly below uses the same numbers).
const OFF_GDT: u64 = 0x100;
const OFF_GDTR: u64 = 0x120;
const OFF_FARPTR32: u64 = 0x128;
const OFF_PARAMS: u64 = 0x130;
const PARAM_CR3: u64 = 0;
const PARAM_STACK: u64 = 8;
const PARAM_ENTRY: u64 = 16;
const PARAM_FLAGS: u64 = 24;
const PARAM_CPU: u64 = 32;
const PARAM_FARPTR64: u64 = 40;
const FLAG_NXE: u64 = 1;
/// Trampoline GDT: null, 32-bit code (0x08), 32-bit data (0x10), 64-bit code (0x18).
const TRAMP_GDT: [u64; 4] = [
    0,
    0x00CF_9A00_0000_FFFF,
    0x00CF_9200_0000_FFFF,
    0x00AF_9A00_0000_FFFF,
];
const SEL_CODE32: u16 = 0x08;
const SEL_CODE64: u16 = 0x18;
/// How long the boot CPU waits for one AP to report in.
const AP_TIMEOUT_MS: u32 = 500;
pub const AP_STACK_SIZE: u64 = 32 * 1024;
pub const AP_DF_STACK_SIZE: u64 = 16 * 1024;

global_asm!(
    r#"
    .section .text
    .code16
    .global ap_tramp_start
ap_tramp_start:
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    xorl %esi, %esi
    movw %cs, %si
    shll $4, %esi
    addl $0x130, %esi
    lgdtl 0x120
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl *0x128
    .global ap_tramp_end
ap_tramp_end:

    .code32
    .global ap_pm32_entry
ap_pm32_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl (%esi), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x100, %eax
    testb $1, 24(%esi)
    jz 1f
    orl $0x800, %eax
1:
    wrmsr
    movl %cr0, %eax
    orl $0x80010001, %eax
    movl %eax, %cr0
    ljmpl *40(%esi)

    .code64
    .global ap_lm64_entry
ap_lm64_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorl %eax, %eax
    movw %ax, %fs
    movw %ax, %gs
    movq 8(%rsi), %rsp
    movq 32(%rsi), %rdi
    movq 16(%rsi), %rax
    xorl %ebp, %ebp
    callq *%rax
    ud2
"#,
    options(att_syntax)
);

extern "C" {
    static ap_tramp_start: u8;
    static ap_tramp_end: u8;
    static ap_pm32_entry: u8;
    static ap_lm64_entry: u8;
}

/// What the boot CPU prepared for one CPU; read by that CPU on its way up.
#[derive(Clone, Copy)]
struct CpuRecord {
    boot_stack: StackInfo,
    df_stack: StackInfo,
}

const NO_RECORD: Option<CpuRecord> = None;
static CPUS: BootCell<[Option<CpuRecord>; MAX_CPUS]> = BootCell::new([NO_RECORD; MAX_CPUS]);
/// Bit `i`: CPU `i` is running the kernel (bit 0 from `init_bsp`).
static ONLINE: AtomicU32 = AtomicU32::new(0);
/// APIC ID per CPU index (the AP writes what its own APIC reports).
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

#[derive(Clone, Copy, Debug, Default)]
pub struct SmpInfo {
    /// Local APICs the MADT lists as usable.
    pub madt_cpus: u32,
    /// CPUs running the kernel at the end of `start_aps`, the boot CPU included.
    pub online: u32,
    pub bsp_apic_id: u32,
    pub trampoline: u64,
    /// Entries skipped: beyond MAX_CPUS, or unaddressable in xAPIC mode.
    pub skipped: u32,
    /// APs that did not report in time (bring-up stops at the first).
    pub failed: u32,
    /// APs whose own APIC ID differs from the MADT's entry (counted, still used).
    pub id_mismatch: u32,
    pub code: &'static str,
}

/// Records the boot CPU (index 0) as online. Before `start_aps`; after `apic::init`.
pub fn init_bsp() {
    APIC_IDS[0].store(apic::my_id(), Ordering::Relaxed);
    ONLINE.fetch_or(1, Ordering::Release);
}

/// Bitmask of CPUs running the kernel.
pub fn online_mask() -> u32 {
    ONLINE.load(Ordering::Acquire)
}

pub fn online_count() -> u32 {
    online_mask().count_ones()
}

/// Local APIC ID of CPU `cpu` (0 for an unknown index).
pub fn apic_id_of(cpu: usize) -> u32 {
    APIC_IDS.get(cpu).map_or(0, |a| a.load(Ordering::Relaxed))
}

fn write_u64(page: u64, off: u64, v: u64) {
    // SAFETY: the trampoline page is identity-mapped RW RAM the kernel chose in `start_aps`;
    // every offset used is inside the page.
    unsafe { ((page + off) as *mut u64).write_volatile(v) };
}

fn write_u32(page: u64, off: u64, v: u32) {
    // SAFETY: as in `write_u64`.
    unsafe { ((page + off) as *mut u32).write_volatile(v) };
}

fn write_u16(page: u64, off: u64, v: u16) {
    // SAFETY: as in `write_u64`.
    unsafe { ((page + off) as *mut u16).write_volatile(v) };
}

/// A low page the kernel maps RW at its own address (identity map of RAM) to hold the
/// trampoline: start address = page number << 12.
fn pick_trampoline_page() -> Option<u8> {
    let ks = vmm::kernel_space()?;
    let space = paging::AddressSpace::from_pml4(ks.cr3, paging::nx_supported());
    (TRAMP_PAGE_FIRST..=TRAMP_PAGE_LAST).find(|&n| {
        let addr = u64::from(n) << 12;
        matches!(space.translate(addr), Some((p, f)) if p == addr && f & paging::WRITE != 0)
    })
}

/// Fills the trampoline page: code, GDT, GDT pointer, far pointer to the 32-bit stage, and the
/// per-boot constants of the params block.
fn install_trampoline(page: u64, kernel_cr3: u64) -> Result<(), &'static str> {
    let start = &raw const ap_tramp_start as u64;
    let end = &raw const ap_tramp_end as u64;
    let pm32 = &raw const ap_pm32_entry as u64;
    let lm64 = &raw const ap_lm64_entry as u64;
    let len = end.checked_sub(start).ok_or("K_E_SMP_TRAMPOLINE")?;
    if len == 0 || len > OFF_GDT || pm32 >= 1 << 32 || lm64 >= 1 << 32 || kernel_cr3 >= 1 << 32 {
        // The 32-bit stage needs its targets and CR3 below 4 GiB.
        return Err("K_E_SMP_IMAGE_HIGH");
    }
    // SAFETY: source is kernel text (readable), destination the chosen RW page; `len` bytes fit
    // below OFF_GDT and the ranges cannot overlap (one is above 1 MiB, the other below).
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, page as *mut u8, len as usize) };
    for (i, d) in TRAMP_GDT.iter().enumerate() {
        write_u64(page, OFF_GDT + 8 * i as u64, *d);
    }
    write_u16(page, OFF_GDTR, (TRAMP_GDT.len() * 8 - 1) as u16);
    write_u32(page, OFF_GDTR + 2, (page + OFF_GDT) as u32);
    write_u32(page, OFF_FARPTR32, pm32 as u32);
    write_u16(page, OFF_FARPTR32 + 4, SEL_CODE32);
    write_u64(page, OFF_PARAMS + PARAM_CR3, kernel_cr3);
    let entry: extern "sysv64" fn(u64) -> ! = ap_start;
    write_u64(page, OFF_PARAMS + PARAM_ENTRY, entry as *const () as u64);
    write_u64(
        page,
        OFF_PARAMS + PARAM_FLAGS,
        if paging::nxe_enabled() { FLAG_NXE } else { 0 },
    );
    write_u32(page, OFF_PARAMS + PARAM_FARPTR64, lm64 as u32);
    write_u16(page, OFF_PARAMS + PARAM_FARPTR64 + 4, SEL_CODE64);
    Ok(())
}

/// Starts every usable AP of the MADT, one after the other, and returns what happened. Runs on
/// the boot CPU with interrupts disabled, after the scheduler is up (the AP joins it).
pub fn start_aps(madt: &Madt, kernel_cr3: u64) -> SmpInfo {
    let mut info = SmpInfo {
        madt_cpus: madt.cpus,
        online: 1,
        bsp_apic_id: apic_id_of(0),
        code: "ok",
        ..SmpInfo::default()
    };
    let Some(page_no) = pick_trampoline_page() else {
        info.code = "K_E_SMP_NO_LOW_PAGE";
        return info;
    };
    let page = u64::from(page_no) << 12;
    info.trampoline = page;
    if let Err(code) = install_trampoline(page, kernel_cr3) {
        info.code = code;
        return info;
    }
    let xapic = apic::mode() == apic::Mode::XApic;
    let mut next = 1usize;
    for &apic_id in &madt.lapic_ids[..madt.n_lapics] {
        if apic_id == info.bsp_apic_id {
            continue;
        }
        if next >= MAX_CPUS || (xapic && apic_id > 0xFE) {
            info.skipped += 1;
            continue;
        }
        let (Ok(boot_stack), Ok(df_stack)) = (
            vmm::alloc_kernel_stack(AP_STACK_SIZE),
            vmm::alloc_kernel_stack(AP_DF_STACK_SIZE),
        ) else {
            info.code = "K_E_SMP_NO_STACK";
            break;
        };
        // SAFETY: slot `next` is written once, here, before the AP that reads it exists
        // (BootCell contract per slot); the fence orders the writes before the IPIs.
        unsafe {
            (*CPUS.get())[next] = Some(CpuRecord {
                boot_stack,
                df_stack,
            });
        }
        write_u64(page, OFF_PARAMS + PARAM_STACK, boot_stack.top());
        write_u64(page, OFF_PARAMS + PARAM_CPU, next as u64);
        fence(Ordering::SeqCst);
        apic::send_init(apic_id);
        pit::wait_ms(10);
        apic::send_sipi(apic_id, page_no);
        pit::wait_us(200);
        apic::send_sipi(apic_id, page_no);
        pit::wait_us(200);
        let bit = 1u32 << next;
        let mut waited = 0u32;
        while online_mask() & bit == 0 && waited < AP_TIMEOUT_MS {
            pit::wait_ms(1);
            waited += 1;
        }
        if online_mask() & bit == 0 {
            // The params block must stay as it is: a late starter would otherwise come up with
            // another CPU's index. No further AP is started.
            info.failed += 1;
            info.code = "K_E_SMP_AP_TIMEOUT";
            break;
        }
        if apic_id_of(next) != apic_id {
            info.id_mismatch += 1;
        }
        next += 1;
    }
    info.online = online_count();
    info
}

/// First Rust code on an application processor: 64-bit mode, paging on with the kernel CR3,
/// RSP at the top of its boot stack, interrupts disabled, trampoline GDT still loaded.
extern "sysv64" fn ap_start(cpu: u64) -> ! {
    let cpu = cpu as usize;
    // SAFETY: slot `cpu` was written by the boot CPU before the SIPI that started this CPU
    // (fence + the IPI's own ordering); nothing writes it again.
    let rec = unsafe { (*CPUS.get())[cpu] }.expect("AP started without a record");
    // Tables and GS first: no lock, no print before this line (cpu_id reads GS).
    super::init_ap_cpu(cpu, rec.df_stack.top(), rec.boot_stack.top());
    let id = apic::init_ap(irq::SPURIOUS_VECTOR, irq::APIC_ERROR_VECTOR);
    APIC_IDS[cpu].store(id, Ordering::Relaxed);
    crate::sched::adopt_ap(cpu, rec.boot_stack);
    irq::timer_start_this_cpu();
    ONLINE.fetch_or(1 << cpu, Ordering::Release);
    // Idle loop: run whatever is placed on this CPU, halt otherwise (interrupts on inside).
    loop {
        if !crate::sched::yield_now() {
            context::idle_wait();
        }
    }
}
