//! QEMU fw_cfg (lab only, test kernel only): reads the test name the host passes with
//! `-fw_cfg name=opt/nawah/test,string=<name>`. Traditional I/O-port interface on x86:
//! selector register 0x510 (16-bit write), data register 0x511 (8-bit reads).
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

fn select(key: u16) {
    // SAFETY: the selector port belongs to fw_cfg alone; the lab adds the device, and reading a
    // missing device returns 0xFF bytes which the signature check rejects.
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
