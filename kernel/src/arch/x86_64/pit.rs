//! 8254 PIT channel 2 as a reference clock for calibration and short waits. Channel 2 raises no
//! interrupt: it is gated and observed through the NMI status/control port 61h, so it works with
//! interrupts disabled and before any APIC setup.
//!
//! References: Intel 8254 datasheet (control word, mode 0 "interrupt on terminal count",
//! 1.193182 MHz input); Intel ICH9 datasheet §13.7 (8254 at ports 40h-43h) and the NMI_SC
//! register at 61h: bit 0 TIM_CNT2_EN (gate), bit 1 SPKR_DAT_EN, bit 5 TMR2_OUT_STS (channel 2
//! output). QEMU models the same bits (hw/audio/pcspk.c: bit 0 gate, bit 1 data, bit 5 OUT,
//! bit 4 refresh toggle). docs/sources.json S34, S35.

use super::port::{inb, outb};

pub const PIT_HZ: u64 = 1_193_182;
const CH2_DATA: u16 = 0x42;
const CONTROL: u16 = 0x43;
const NMI_SC: u16 = 0x61;
/// Control word: channel 2, access low byte then high byte, mode 0, binary.
const CH2_MODE0_LOHI: u8 = 0b1011_0000;
/// Longest wait a 16-bit count allows (65535 / 1193182 s).
pub const MAX_WAIT_MS: u64 = 54;

/// Busy-waits `ms` milliseconds (1..=54) on PIT channel 2 in mode 0: OUT goes low when the count
/// is loaded and high when it reaches zero. Returns false if the output never rose (hardware
/// absent), after a bounded number of polls.
pub fn wait_ms(ms: u64) -> bool {
    let ms = ms.clamp(1, MAX_WAIT_MS);
    let count = (PIT_HZ * ms / 1000) as u16;
    // SAFETY: standard PIT/NMI_SC ports; only channel 2 and the gate/speaker bits are touched,
    // the speaker stays off (bit 1 = 0); interrupts need not be disabled for this to be correct.
    unsafe {
        // Gate low, speaker off, then program the count (mode 0 waits for the gate to go high).
        let sc = inb(NMI_SC) & !0x03;
        outb(NMI_SC, sc);
        outb(CONTROL, CH2_MODE0_LOHI);
        outb(CH2_DATA, count as u8);
        outb(CH2_DATA, (count >> 8) as u8);
        // Gate high starts the countdown.
        outb(NMI_SC, sc | 0x01);
        // Poll OUT (bit 5). A bound of 2^26 polls is minutes even on a slow emulator.
        let mut polls: u32 = 0;
        while inb(NMI_SC) & 0x20 == 0 {
            polls += 1;
            if polls == 1 << 26 {
                outb(NMI_SC, sc);
                return false;
            }
        }
        outb(NMI_SC, sc);
    }
    true
}
