//! ACPI table discovery for the interrupt controllers: RSDP -> XSDT (or RSDT) -> MADT.
//! Read-only, no allocation; the tables live in ACPI-reclaim/NVS RAM, which the kernel address
//! space identity-maps (WP-09), so physical addresses are used directly.
//!
//! References (ACPI 6.5, docs/sources.json S33): §5.2.5.3 Table 5.3 RSDP (Revision at byte 15,
//! RsdtAddress at 16, XsdtAddress at 24; bytes 0..20 sum to zero, and for revision >= 2 the whole
//! table sums to zero); §5.2.6 Table 5.4 DESCRIPTION_HEADER (36 bytes; Length at 4; the whole
//! table sums to zero); §5.2.8 XSDT (8-byte entries from offset 36; must be used when present);
//! §5.2.12 MADT: Local Interrupt Controller Address at 36, Flags at 40 (bit 0 PCAT_COMPAT), then
//! Interrupt Controller Structures (type, length): 0 Processor Local APIC (Table 5.22: APIC ID at
//! 3, Flags at 4: bit 0 Enabled, bit 1 Online Capable), 1 I/O APIC (Table 5.24: ID at 2, address
//! at 4, GSI base at 8), 2 Interrupt Source Override (Table 5.25: source IRQ at 3, GSI at 4,
//! MPS INTI flags at 8: polarity bits 0-1, trigger bits 2-3), 5 Local APIC Address Override
//! (Table 5.29: 64-bit address at 4), 9 Processor Local x2APIC (Table 5.34: x2APIC ID at 4,
//! Flags at 8).

pub const MAX_IOAPICS: usize = 4;
pub const MAX_OVERRIDES: usize = 16;

#[derive(Clone, Copy, Default, Debug)]
pub struct IoApic {
    #[allow(dead_code)] // consumed by the IRQ routing of M3/M4
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

/// ISA IRQ -> GSI override; consumed by the IRQ routing of M3/M4, parsed now so the MADT walk is
/// complete and tested.
#[allow(dead_code)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Override {
    pub source_irq: u8,
    pub gsi: u32,
    /// MPS INTI flags: polarity bits 0-1 (01 high, 11 low), trigger bits 2-3 (01 edge, 11 level).
    pub flags: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Madt {
    pub lapic_address: u64,
    pub pcat_compat: bool,
    /// Local APICs flagged Enabled (or Online Capable), counting both type 0 and type 9 entries.
    pub cpus: u32,
    pub ioapics: [IoApic; MAX_IOAPICS],
    pub n_ioapics: usize,
    pub overrides: [Override; MAX_OVERRIDES],
    pub n_overrides: usize,
    /// Structures the parser skipped because the fixed arrays were full.
    pub dropped: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcpiError {
    NoRsdp,
    BadRsdpSignature,
    BadRsdpChecksum,
    NoRootTable,
    BadRootTable,
    NoMadt,
    BadMadt,
}

impl AcpiError {
    pub fn code(&self) -> &'static str {
        match self {
            AcpiError::NoRsdp => "K_E_ACPI_NO_RSDP",
            AcpiError::BadRsdpSignature => "K_E_ACPI_RSDP_SIGNATURE",
            AcpiError::BadRsdpChecksum => "K_E_ACPI_RSDP_CHECKSUM",
            AcpiError::NoRootTable => "K_E_ACPI_NO_ROOT_TABLE",
            AcpiError::BadRootTable => "K_E_ACPI_BAD_ROOT_TABLE",
            AcpiError::NoMadt => "K_E_ACPI_NO_MADT",
            AcpiError::BadMadt => "K_E_ACPI_BAD_MADT",
        }
    }
}

const HEADER_LEN: u64 = 36;
/// Largest table this parser walks; a corrupt Length field cannot send it across memory.
const MAX_TABLE_LEN: u64 = 1 << 20;

fn rd8(addr: u64) -> u8 {
    // SAFETY: addresses come from ACPI structures whose bounds were checked by the caller and
    // lie in identity-mapped RAM; a byte read has no alignment requirement.
    unsafe { (addr as *const u8).read_volatile() }
}

fn rd16(addr: u64) -> u16 {
    u16::from_le_bytes([rd8(addr), rd8(addr + 1)])
}

fn rd32(addr: u64) -> u32 {
    u32::from_le_bytes([rd8(addr), rd8(addr + 1), rd8(addr + 2), rd8(addr + 3)])
}

fn rd64(addr: u64) -> u64 {
    u64::from(rd32(addr)) | (u64::from(rd32(addr + 4)) << 32)
}

fn sums_to_zero(addr: u64, len: u64) -> bool {
    let mut sum: u8 = 0;
    let mut i = 0;
    while i < len {
        sum = sum.wrapping_add(rd8(addr + i));
        i += 1;
    }
    sum == 0
}

fn signature(addr: u64) -> [u8; 4] {
    [rd8(addr), rd8(addr + 1), rd8(addr + 2), rd8(addr + 3)]
}

/// Validates a DESCRIPTION_HEADER table at `addr`: signature, sane length, checksum.
fn checked_table(addr: u64, sig: &[u8; 4]) -> Option<u64> {
    if addr == 0 || signature(addr) != *sig {
        return None;
    }
    let len = u64::from(rd32(addr + 4));
    if !(HEADER_LEN..=MAX_TABLE_LEN).contains(&len) || !sums_to_zero(addr, len) {
        return None;
    }
    Some(len)
}

/// Finds the MADT starting from the RSDP physical address and extracts what the interrupt
/// bring-up needs.
pub fn parse_madt(rsdp: u64) -> Result<Madt, AcpiError> {
    if rsdp == 0 {
        return Err(AcpiError::NoRsdp);
    }
    let sig = [
        rd8(rsdp),
        rd8(rsdp + 1),
        rd8(rsdp + 2),
        rd8(rsdp + 3),
        rd8(rsdp + 4),
        rd8(rsdp + 5),
        rd8(rsdp + 6),
        rd8(rsdp + 7),
    ];
    if &sig != b"RSD PTR " {
        return Err(AcpiError::BadRsdpSignature);
    }
    if !sums_to_zero(rsdp, 20) {
        return Err(AcpiError::BadRsdpChecksum);
    }
    let revision = rd8(rsdp + 15);
    // Root table: XSDT (64-bit entries) when the revision offers it; RSDT (32-bit) otherwise.
    let (root, entry_size) = if revision >= 2 {
        let len = u64::from(rd32(rsdp + 20));
        if !(36..=4096).contains(&len) || !sums_to_zero(rsdp, len) {
            return Err(AcpiError::BadRsdpChecksum);
        }
        let xsdt = rd64(rsdp + 24);
        if xsdt != 0 {
            (checked_table(xsdt, b"XSDT").map(|l| (xsdt, l)), 8u64)
        } else {
            let rsdt = u64::from(rd32(rsdp + 16));
            (checked_table(rsdt, b"RSDT").map(|l| (rsdt, l)), 4u64)
        }
    } else {
        let rsdt = u64::from(rd32(rsdp + 16));
        (checked_table(rsdt, b"RSDT").map(|l| (rsdt, l)), 4u64)
    };
    let Some((root, root_len)) = root else {
        return Err(
            if revision >= 2 && rd64(rsdp + 24) == 0 && rd32(rsdp + 16) == 0 {
                AcpiError::NoRootTable
            } else {
                AcpiError::BadRootTable
            },
        );
    };
    let n = (root_len - HEADER_LEN) / entry_size;
    let mut madt = 0u64;
    for i in 0..n {
        let e = root + HEADER_LEN + i * entry_size;
        let table = if entry_size == 8 {
            rd64(e)
        } else {
            u64::from(rd32(e))
        };
        if table != 0 && signature(table) == *b"APIC" {
            madt = table;
            break;
        }
    }
    if madt == 0 {
        return Err(AcpiError::NoMadt);
    }
    let Some(len) = checked_table(madt, b"APIC") else {
        return Err(AcpiError::BadMadt);
    };
    if len < HEADER_LEN + 8 {
        return Err(AcpiError::BadMadt);
    }
    let mut out = Madt {
        lapic_address: u64::from(rd32(madt + 36)),
        pcat_compat: rd32(madt + 40) & 1 != 0,
        cpus: 0,
        ioapics: [IoApic::default(); MAX_IOAPICS],
        n_ioapics: 0,
        overrides: [Override::default(); MAX_OVERRIDES],
        n_overrides: 0,
        dropped: 0,
    };
    let mut off = HEADER_LEN + 8;
    while off + 2 <= len {
        let typ = rd8(madt + off);
        let slen = u64::from(rd8(madt + off + 1));
        if slen < 2 || off + slen > len {
            return Err(AcpiError::BadMadt);
        }
        let s = madt + off;
        match typ {
            0 if slen >= 8 && rd32(s + 4) & 0b11 != 0 => out.cpus += 1,
            1 if slen >= 12 => {
                if out.n_ioapics < MAX_IOAPICS {
                    out.ioapics[out.n_ioapics] = IoApic {
                        id: rd8(s + 2),
                        address: rd32(s + 4),
                        gsi_base: rd32(s + 8),
                    };
                    out.n_ioapics += 1;
                } else {
                    out.dropped += 1;
                }
            }
            2 if slen >= 10 => {
                if out.n_overrides < MAX_OVERRIDES {
                    out.overrides[out.n_overrides] = Override {
                        source_irq: rd8(s + 3),
                        gsi: rd32(s + 4),
                        flags: rd16(s + 8),
                    };
                    out.n_overrides += 1;
                } else {
                    out.dropped += 1;
                }
            }
            5 if slen >= 12 => out.lapic_address = rd64(s + 4),
            9 if slen >= 16 && rd32(s + 8) & 0b11 != 0 => out.cpus += 1,
            _ => {}
        }
        off += slen;
    }
    Ok(out)
}
