//! QEMU fw_cfg. The test kernel reads the test name the host passes with
//! `-fw_cfg name=opt/nawah/test,string=<name>`. The release kernel runs this reader too
//! (WP-45, docs/contracts/boot.md v1.1 "boot mode"): it reads the boot-mode key
//! `opt/nawah/selftest`, and only after `hypervisor_present` (CPUID.01H:ECX[31]) is set, so no
//! fw_cfg port is touched on bare hardware. Traditional I/O-port interface on x86: selector
//! register 0x510 (16-bit write), data register 0x511 (8-bit reads); both ports are constants.
//! Declared failure mode (boot.md v1.1): a hypervisor other than QEMU that sets the bit gets the
//! selector write before the signature check can reject it; its effect there is unverified.
//! Source: QEMU docs/specs/fw_cfg.rst (selector/data ports, FW_CFG_SIGNATURE 0x0000 = "QEMU",
//! FW_CFG_FILE_DIR 0x0019: big-endian u32 count then entries {u32 size, u16 select, u16 reserved,
//! char name[56]}, all big-endian).

use super::port::{inb, outw};

const SELECTOR: u16 = 0x510;
const DATA: u16 = 0x511;
const FW_CFG_SIGNATURE: u16 = 0x0000;
const FW_CFG_FILE_DIR: u16 = 0x0019;
const NAME_LEN: usize = 56;
/// Upper bound on directory entries we are willing to scan.
const MAX_ENTRIES: u32 = 256;

/// CPUID.01H:ECX bit 31: a hypervisor is present (zero on bare hardware). The release kernel
/// gates every fw_cfg access on it (boot.md v1.1, boot mode step 1).
#[cfg(not(feature = "ktest"))]
const CPUID_ECX_HYPERVISOR: u32 = 1 << 31;

/// Whether the CPU reports a hypervisor (CPUID.01H:ECX[31]); fw_cfg is read only when it does.
#[cfg(not(feature = "ktest"))]
pub fn hypervisor_present() -> bool {
    // `__cpuid` is a safe intrinsic on x86_64 (leaf 1 exists on every x86-64 CPU).
    core::arch::x86_64::__cpuid(1).ecx & CPUID_ECX_HYPERVISOR != 0
}

fn select(key: u16) {
    // SAFETY: the port is the constant fw_cfg selector (0x510). `key` is a constant (signature,
    // file directory) or the select key of an entry read from the file directory after the
    // signature matched. The release kernel calls this only behind the CPUID.01H:ECX[31] gate;
    // on QEMU the device is there, and a missing device reads back 0xFF bytes which the
    // signature check rejects. Under a non-QEMU hypervisor that sets the bit, the first write
    // (key 0x0000) lands before the signature check; its effect is unverified (boot.md v1.1).
    unsafe { outw(SELECTOR, key) }
}

fn read_u8() -> u8 {
    // SAFETY: as in `select`.
    unsafe { inb(DATA) }
}

fn read_be32() -> u32 {
    let mut v = 0u32;
    for _ in 0..4 {
        v = (v << 8) | u32::from(read_u8());
    }
    v
}

fn read_be16() -> u16 {
    let mut v = 0u16;
    for _ in 0..2 {
        v = (v << 8) | u16::from(read_u8());
    }
    v
}

/// Reads the fw_cfg file `name` into `buf`; returns the number of bytes copied, or None if the
/// device or the file is absent.
pub fn read_file(name: &str, buf: &mut [u8]) -> Option<usize> {
    select(FW_CFG_SIGNATURE);
    let mut sig = [0u8; 4];
    for b in sig.iter_mut() {
        *b = read_u8();
    }
    if &sig != b"QEMU" {
        return None;
    }
    select(FW_CFG_FILE_DIR);
    let count = read_be32().min(MAX_ENTRIES);
    let mut found: Option<(u32, u16)> = None;
    for _ in 0..count {
        let size = read_be32();
        let key = read_be16();
        let _reserved = read_be16();
        let mut entry_name = [0u8; NAME_LEN];
        for b in entry_name.iter_mut() {
            *b = read_u8();
        }
        let end = entry_name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        if found.is_none() && &entry_name[..end] == name.as_bytes() {
            found = Some((size, key));
            // keep reading to leave the directory stream consistent
        }
    }
    let (size, key) = found?;
    select(key);
    let n = (size as usize).min(buf.len());
    for b in buf.iter_mut().take(n) {
        *b = read_u8();
    }
    Some(n)
}
