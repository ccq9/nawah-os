//! Interrupt (vector >= 32) dispatch and the WP-10 bring-up: PIC masked, local APIC enabled and
//! calibrated, I/O APICs masked, periodic timer. Handlers never print: they count and return.
//! Interrupt gates keep IF clear while a handler runs, so a handler cannot be re-entered; the
//! depth counter below proves it in the test kernel.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{acpi, apic, ioapic, pic};
use crate::cell::BootCell;

/// Vector assignments (0x20..=0x2F belong to the masked PIC; 0xFF is spurious, SDM §11.9).
pub const TIMER_VECTOR: u8 = 0x40;
pub const TEST_IPI_VECTOR: u8 = 0x41;
pub const APIC_ERROR_VECTOR: u8 = 0xFE;
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// Periodic timer rate.
pub const TIMER_HZ: u32 = 1000;

pub type Handler = fn();

static HANDLERS: BootCell<[Option<Handler>; 256]> = BootCell::new([None; 256]);

static TICKS: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static UNEXPECTED: AtomicU32 = AtomicU32::new(0);
static SPURIOUS: AtomicU32 = AtomicU32::new(0);
static LAST_UNEXPECTED_VECTOR: AtomicU32 = AtomicU32::new(0);
static DEPTH: AtomicU32 = AtomicU32::new(0);
static MAX_DEPTH: AtomicU32 = AtomicU32::new(0);
static TEST_IPIS: AtomicU32 = AtomicU32::new(0);

fn timer_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

fn test_ipi() {
    TEST_IPIS.fetch_add(1, Ordering::Relaxed);
}

/// Registers `handler` for `vector` (boot path, before interrupts are enabled).
pub fn register(vector: u8, handler: Handler) {
    // SAFETY: boot path, single CPU, interrupts disabled (BootCell contract); the table is read
    // by `dispatch` only after registration.
    unsafe { (*HANDLERS.get())[usize::from(vector)] = Some(handler) };
}

/// Called by the common trap path for every vector >= 32, with interrupts disabled.
pub fn dispatch(vector: u8) {
    let depth = DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
    MAX_DEPTH.fetch_max(depth, Ordering::Relaxed);
    TOTAL.fetch_add(1, Ordering::Relaxed);
    if vector == SPURIOUS_VECTOR {
        // No EOI for a spurious interrupt (SDM §11.9).
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        DEPTH.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: the table is only written on the boot path before interrupts are enabled, so a
    // read from an interrupt handler never overlaps a write.
    let handler = unsafe { (*HANDLERS.get())[usize::from(vector)] };
    match handler {
        Some(h) => h(),
        None => {
            UNEXPECTED.fetch_add(1, Ordering::Relaxed);
            LAST_UNEXPECTED_VECTOR.store(u32::from(vector), Ordering::Relaxed);
        }
    }
    apic::eoi();
    DEPTH.fetch_sub(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug)]
pub struct IrqInfo {
    pub pic_masks: (u8, u8),
    pub lapic: apic::Lapic,
    pub svr: u32,
    pub cpus: u32,
    pub ioapics: u32,
    pub ioapic_entries: u32,
    /// Redirection entries read back as masked after init (must equal `ioapic_entries`).
    pub ioapic_masked: u32,
    pub ioapic_version: u8,
    pub overrides: u32,
    pub pcat_compat: bool,
    pub timer_hz: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum IrqError {
    Acpi(acpi::AcpiError),
    Apic(apic::ApicError),
    IoApic(ioapic::IoApicError),
    TimerNotCalibrated,
}

impl IrqError {
    pub fn code(&self) -> &'static str {
        match self {
            IrqError::Acpi(e) => e.code(),
            IrqError::Apic(e) => e.code(),
            IrqError::IoApic(_) => "K_E_IOAPIC_MMIO",
            IrqError::TimerNotCalibrated => "K_E_TIMER_NOT_CALIBRATED",
        }
    }
}

/// Stops the periodic timer (the tick counter keeps its value).
pub fn timer_stop() {
    apic::timer_stop();
}

/// WP-10 bring-up, with interrupts disabled: MADT, PIC remap+mask, LAPIC (spurious 0xFF, error
/// 0xFE) with timer calibration, every I/O APIC masked, then the periodic timer on 0x40 at
/// TIMER_HZ. Interrupts stay disabled; the caller enables them when it is ready.
pub fn init(rsdp: u64) -> Result<IrqInfo, IrqError> {
    let madt = acpi::parse_madt(rsdp).map_err(IrqError::Acpi)?;
    let pic_masks = pic::remap_and_mask_all();
    register(TIMER_VECTOR, timer_tick);
    register(TEST_IPI_VECTOR, test_ipi);
    let lapic = apic::init(madt.lapic_address, SPURIOUS_VECTOR, APIC_ERROR_VECTOR)
        .map_err(IrqError::Apic)?;
    let (mut entries, mut masked, mut version) = (0, 0, 0);
    for io in &madt.ioapics[..madt.n_ioapics] {
        let i = ioapic::init(io.address, io.gsi_base).map_err(IrqError::IoApic)?;
        entries += i.entries;
        masked += ioapic::masked_entries(&i);
        version = i.version;
    }
    if !apic::timer_start_periodic(TIMER_VECTOR, TIMER_HZ) {
        return Err(IrqError::TimerNotCalibrated);
    }
    Ok(IrqInfo {
        pic_masks,
        lapic,
        svr: apic::svr(),
        cpus: madt.cpus,
        ioapics: madt.n_ioapics as u32,
        ioapic_entries: entries,
        ioapic_masked: masked,
        ioapic_version: version,
        overrides: madt.n_overrides as u32,
        pcat_compat: madt.pcat_compat,
        timer_hz: TIMER_HZ,
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub ticks: u64,
    pub total: u64,
    pub unexpected: u32,
    pub last_unexpected_vector: u32,
    pub spurious: u32,
    pub max_depth: u32,
    /// Test-IPI deliveries (test kernel; always 0 in the shipped kernel).
    #[allow(dead_code)]
    pub test_ipis: u32,
}

pub fn counters() -> Counters {
    Counters {
        ticks: TICKS.load(Ordering::Relaxed),
        total: TOTAL.load(Ordering::Relaxed),
        unexpected: UNEXPECTED.load(Ordering::Relaxed),
        last_unexpected_vector: LAST_UNEXPECTED_VECTOR.load(Ordering::Relaxed),
        spurious: SPURIOUS.load(Ordering::Relaxed),
        max_depth: MAX_DEPTH.load(Ordering::Relaxed),
        test_ipis: TEST_IPIS.load(Ordering::Relaxed),
    }
}
