//! PL011 UART on QEMU `virt` (hw/arm/virt.c: VIRT_UART at 0x0900_0000). The firmware (AAVMF)
//! has already configured it as its console, so only the data and flag registers are used:
//! UARTDR at +0x00, UARTFR at +0x18 with bit 5 TXFF (transmit FIFO full) — Arm PrimeCell UART
//! (PL011) Technical Reference Manual, §3.3. Lab-specific base address: a real port discovers
//! it from the SPCR/DBG2 ACPI tables or the device tree (recorded in ADR-0008).

use core::fmt;

const UART_BASE: u64 = 0x0900_0000;
const UARTDR: u64 = 0x00;
const UARTFR: u64 = 0x18;
const FR_TXFF: u32 = 1 << 5;
const SPIN_LIMIT: u32 = 100_000;

pub struct Serial;

impl Serial {
    /// Nothing to program: the firmware console setup is reused.
    pub fn init() {}

    fn put(byte: u8) {
        let mut spins = 0;
        // SAFETY: fixed MMIO registers of the lab's UART, mapped by the firmware's identity
        // tables; 32-bit volatile accesses as the PL011 TRM requires.
        unsafe {
            while ((UART_BASE + UARTFR) as *const u32).read_volatile() & FR_TXFF != 0 {
                spins += 1;
                if spins == SPIN_LIMIT {
                    return; // never block the kernel on a silent device
                }
            }
            ((UART_BASE + UARTDR) as *mut u32).write_volatile(u32::from(byte));
        }
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            Self::put(b);
        }
        Ok(())
    }
}
