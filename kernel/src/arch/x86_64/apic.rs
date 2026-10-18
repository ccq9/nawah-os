//! Local APIC: xAPIC (MMIO) or x2APIC (MSR) register access, software enable with a spurious
//! vector, EOI, self-IPI, and the APIC timer calibrated against the PIT.
//!
//! References (Intel SDM Vol. 3A, docs/sources.json S26): §11.4.4 IA32_APIC_BASE MSR (1BH: bit 8
//! BSP, bit 10 x2APIC enable, bit 11 global enable, bits 12+ base); Table 11-1 register map
//! (ID 20H, Version 30H, TPR 80H, EOI B0H, SVR F0H, ISR 100H.., IRR 200H.., ESR 280H, ICR 300H/
//! 310H, LVT Timer 320H, LVT LINT0 350H, LVT LINT1 360H, LVT Error 370H, Initial Count 380H,
//! Current Count 390H, Divide Configuration 3E0H); §11.5.1 LVT (bit 16 mask, bits 17-18 timer
//! mode 00 one-shot 01 periodic); §11.5.4 timer (DCR encoding bits 0,1,3: 1011b = divide by 1);
//! §11.6.1 ICR (bits 18-19 shorthand 01 = self, bit 12 delivery status); §11.8.5 EOI (write 0);
//! §11.9 spurious interrupt (SVR bit 8 enable, bits 0-7 vector; the handler must not EOI);
//! §11.12 x2APIC (MSR 800H + offset/16, ICR as one 64-bit MSR 830H).
//!
//! The lab's APIC timer runs at 1 GHz (QEMU 8.2 hw/intc/apic_common.c counts virtual-clock
//! nanoseconds shifted by the divide configuration); real hardware differs, hence calibration.

use core::arch::asm;

use super::pit;
use crate::cell::BootCell;
use crate::mm::vmm;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const REG_ID: u32 = 0x020;
const REG_VERSION: u32 = 0x030;
const REG_TPR: u32 = 0x080;
const REG_EOI: u32 = 0x0B0;
const REG_SVR: u32 = 0x0F0;
const REG_ESR: u32 = 0x280;
const REG_ICR_LOW: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_LINT0: u32 = 0x350;
const REG_LVT_LINT1: u32 = 0x360;
const REG_LVT_ERROR: u32 = 0x370;
const REG_TIMER_INITIAL: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3E0;

const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const SVR_ENABLE: u32 = 1 << 8;
#[cfg(feature = "ktest")]
const ICR_SHORTHAND_SELF: u32 = 0b01 << 18;
const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// ICR delivery modes (§11.6.1, bits 8-10) and the level bit (14, asserted).
const ICR_FIXED: u32 = 0b000 << 8;
const ICR_INIT: u32 = 0b101 << 8;
const ICR_STARTUP: u32 = 0b110 << 8;
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const DIVIDE_BY_1: u32 = 0b1011;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    XApic,
    X2Apic,
}

#[derive(Clone, Copy, Debug)]
pub struct Lapic {
    pub mode: Mode,
    /// Address of the xAPIC register page in the kernel's MMIO window (0 in x2APIC mode).
    pub base: u64,
    pub id: u32,
    pub version: u32,
    /// Calibrated timer input frequency (ticks per second at divide-by-1); 0 if calibration
    /// failed.
    pub timer_hz: u64,
}

static LAPIC: BootCell<Option<Lapic>> = BootCell::new(None);

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdmsr at CPL 0 of an architectural MSR.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: wrmsr at CPL 0; callers write only architectural APIC MSRs with valid values.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack))
    };
}

fn current() -> Lapic {
    // SAFETY: read of a BootCell written once by `init` (callers run after it).
    unsafe { (*LAPIC.get()).expect("lapic::init not called") }
}

fn read(reg: u32) -> u32 {
    let l = current();
    match l.mode {
        Mode::XApic => {
            // SAFETY: the MMIO page was mapped uncacheable by `init`; registers are 32-bit and
            // 16-byte aligned (Table 11-1).
            unsafe { ((l.base + u64::from(reg)) as *const u32).read_volatile() }
        }
        Mode::X2Apic => rdmsr(0x800 + (reg >> 4)) as u32,
    }
}

fn write(reg: u32, value: u32) {
    let l = current();
    match l.mode {
        Mode::XApic => {
            // SAFETY: as in `read`.
            unsafe { ((l.base + u64::from(reg)) as *mut u32).write_volatile(value) }
        }
        Mode::X2Apic => wrmsr(0x800 + (reg >> 4), u64::from(value)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApicError {
    /// IA32_APIC_BASE has the global enable bit clear; re-enabling needs a reset on most parts.
    Disabled,
    Mmio,
}

impl ApicError {
    pub fn code(&self) -> &'static str {
        match self {
            ApicError::Disabled => "K_E_APIC_DISABLED",
            ApicError::Mmio => "K_E_APIC_MMIO",
        }
    }
}

/// Brings the local APIC up in the mode the firmware left it in: maps the xAPIC page (or uses
/// the x2APIC MSRs), software-enables it with `spurious_vector`, masks LINT0/LINT1, points the
/// error LVT at `error_vector`, masks the timer, and calibrates the timer against the PIT.
pub fn init(madt_base: u64, spurious_vector: u8, error_vector: u8) -> Result<Lapic, ApicError> {
    let msr = rdmsr(IA32_APIC_BASE);
    if msr & APIC_BASE_ENABLE == 0 {
        return Err(ApicError::Disabled);
    }
    let (mode, base) = if msr & APIC_BASE_X2APIC != 0 {
        (Mode::X2Apic, 0)
    } else {
        let phys = if madt_base != 0 {
            madt_base
        } else {
            msr & APIC_BASE_ADDR_MASK
        };
        // The register page lives in the kernel's MMIO window from here on (never at `phys`).
        let base = vmm::map_mmio(phys, 4096).map_err(|_| ApicError::Mmio)?;
        (Mode::XApic, base)
    };
    // SAFETY: boot path, single write (BootCell contract).
    unsafe {
        LAPIC.get().write(Some(Lapic {
            mode,
            base,
            id: 0,
            version: 0,
            timer_hz: 0,
        }))
    };
    let id = match mode {
        Mode::XApic => read(REG_ID) >> 24,
        Mode::X2Apic => read(REG_ID),
    };
    let version = read(REG_VERSION);
    // Software-enable first: while disabled, LVT mask bits are forced to 1 (§11.4.7.2).
    write(REG_SVR, SVR_ENABLE | u32::from(spurious_vector));
    write(REG_TPR, 0);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_LVT_LINT0, LVT_MASKED);
    write(REG_LVT_LINT1, LVT_MASKED);
    write(REG_LVT_ERROR, u32::from(error_vector));
    // ESR: write before read (§11.5.3), clears stale error bits.
    write(REG_ESR, 0);
    let timer_hz = calibrate_timer();
    let l = Lapic {
        mode,
        base,
        id,
        version,
        timer_hz,
    };
    // SAFETY: boot path, before any interrupt can observe the record.
    unsafe { LAPIC.get().write(Some(l)) };
    Ok(l)
}

/// Measures the timer input frequency: divide by 1, one-shot from 0xFFFF_FFFF, PIT 10 ms, read
/// the current count. Returns 0 if the PIT reference is missing or the count did not move.
fn calibrate_timer() -> u64 {
    write(REG_TIMER_DIVIDE, DIVIDE_BY_1);
    write(REG_LVT_TIMER, LVT_MASKED); // one-shot, masked: no interrupt during calibration
    write(REG_TIMER_INITIAL, u32::MAX);
    let ok = pit::wait_ms(10);
    let current = read(REG_TIMER_CURRENT);
    write(REG_TIMER_INITIAL, 0); // stop
    let elapsed = u64::from(u32::MAX - current);
    if !ok || elapsed < 1000 {
        return 0;
    }
    elapsed * 100
}

/// Starts the periodic timer at `hz` on `vector` (needs a calibrated frequency).
pub fn timer_start_periodic(vector: u8, hz: u32) -> bool {
    let l = current();
    if l.timer_hz == 0 || hz == 0 {
        return false;
    }
    let initial = (l.timer_hz / u64::from(hz)).clamp(1, u64::from(u32::MAX)) as u32;
    write(REG_TIMER_DIVIDE, DIVIDE_BY_1);
    write(REG_LVT_TIMER, u32::from(vector) | LVT_TIMER_PERIODIC);
    write(REG_TIMER_INITIAL, initial);
    true
}

/// Masks the timer and stops it.
pub fn timer_stop() {
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_TIMER_INITIAL, 0);
}

/// Signals end of interrupt for the in-service vector.
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Sends a fixed interrupt on `vector` to this CPU (destination shorthand "self"). Test kernel
/// for now; M3 (SMP) generalises the destination.
#[cfg(feature = "ktest")]
pub fn send_self_ipi(vector: u8) {
    let l = current();
    match l.mode {
        Mode::XApic => {
            write(REG_ICR_HIGH, 0);
            write(REG_ICR_LOW, ICR_SHORTHAND_SELF | u32::from(vector));
            // Wait for the delivery-status bit so a second IPI cannot overwrite the first.
            let mut spins = 0u32;
            while read(REG_ICR_LOW) & ICR_DELIVERY_PENDING != 0 && spins < 1_000_000 {
                spins += 1;
            }
        }
        Mode::X2Apic => wrmsr(0x830, u64::from(ICR_SHORTHAND_SELF | u32::from(vector))),
    }
}

/// Spurious-vector register read-back (test kernel diagnostics).
pub fn svr() -> u32 {
    read(REG_SVR)
}

/// The mode the local APICs run in (the firmware's choice, read at `init`).
pub fn mode() -> Mode {
    current().mode
}

/// This CPU's local APIC ID as the hardware reports it (xAPIC: ID register bits 24-31; x2APIC:
/// the whole register).
pub fn my_id() -> u32 {
    match current().mode {
        Mode::XApic => read(REG_ID) >> 24,
        Mode::X2Apic => read(REG_ID),
    }
}

/// Writes the ICR for destination `apic_id` (physical mode) with `low` (vector, delivery mode,
/// level) and waits for the delivery-status bit to clear in xAPIC mode (§11.6.1: a new IPI
/// must not be written while the previous one is pending). Bounded wait.
fn write_icr(apic_id: u32, low: u32) {
    match current().mode {
        Mode::XApic => {
            let mut spins = 0u32;
            while read(REG_ICR_LOW) & ICR_DELIVERY_PENDING != 0 && spins < 1_000_000 {
                spins += 1;
                core::hint::spin_loop();
            }
            write(REG_ICR_HIGH, apic_id << 24);
            write(REG_ICR_LOW, low);
            spins = 0;
            while read(REG_ICR_LOW) & ICR_DELIVERY_PENDING != 0 && spins < 1_000_000 {
                spins += 1;
                core::hint::spin_loop();
            }
        }
        Mode::X2Apic => wrmsr(0x830, (u64::from(apic_id) << 32) | u64::from(low)),
    }
}

/// Fixed interrupt `vector` to the CPU whose local APIC ID is `apic_id` (WP-20).
pub fn send_ipi(apic_id: u32, vector: u8) {
    write_icr(apic_id, ICR_FIXED | ICR_LEVEL_ASSERT | u32::from(vector));
}

/// INIT IPI (level asserted) to `apic_id`: the AP enters the wait-for-SIPI state (§9.4.4).
pub fn send_init(apic_id: u32) {
    write_icr(apic_id, ICR_INIT | ICR_LEVEL_ASSERT);
}

/// Start-up IPI to `apic_id`: the AP starts in real mode at `page << 12` (`page` < 0x100).
pub fn send_sipi(apic_id: u32, page: u8) {
    write_icr(apic_id, ICR_STARTUP | ICR_LEVEL_ASSERT | u32::from(page));
}

/// Brings up the local APIC of an application processor (WP-20): same mode and register page
/// as the boot CPU's (`init` recorded them), software enable with the same vectors, LINT0/1
/// and timer masked, ESR cleared. Returns this CPU's APIC ID.
pub fn init_ap(spurious_vector: u8, error_vector: u8) -> u32 {
    write(REG_SVR, SVR_ENABLE | u32::from(spurious_vector));
    write(REG_TPR, 0);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_LVT_LINT0, LVT_MASKED);
    write(REG_LVT_LINT1, LVT_MASKED);
    write(REG_LVT_ERROR, u32::from(error_vector));
    write(REG_ESR, 0);
    my_id()
}
