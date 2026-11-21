//! Boot mode (WP-45, docs/contracts/boot.md v1.1 "boot mode"; PLAN-ANSWER §2.1): one release
//! image, two modes decided once at run time after the handoff. `selftest` (the lab self-test:
//! `/SYSTEM/SELFTEST.TXT`, then the M1 exit) only when, in this order and each step only after
//! the one before succeeded: CPUID.01H:ECX[31] reports a hypervisor, the fw_cfg signature is
//! `QEMU`, and the fw_cfg file `opt/nawah/selftest` holds exactly the one byte `1`. Everything
//! else is `interactive` (the system manifest `/SYSTEM/SERVICES.TXT`, no exit), including the
//! test kernel's key `opt/nawah/test`, which this module never reads. The key selects; it never
//! carries a path (services.md v1.11 §0.000).

use core::fmt;

use crate::arch::fwcfg;

/// The fw_cfg file that selects the lab self-test (`-fw_cfg name=opt/nawah/selftest,string=1`).
const SELFTEST_KEY: &str = "opt/nawah/selftest";

/// What the boot read of the key: `Ok` (exactly `1`), `Invalid` (present, any other content,
/// `1` followed by any byte included) or `Absent` (no hypervisor, no signature, or no file).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Ok,
    Absent,
    Invalid,
}

/// The decided mode: the hypervisor bit and the key; `selftest` exactly when the key is `Ok`.
#[derive(Clone, Copy)]
pub struct BootMode {
    hv: bool,
    key: Key,
}

impl BootMode {
    /// Whether this boot is the lab self-test (boot.md v1.1: only the key `1` gives it).
    pub fn selftest(&self) -> bool {
        self.key == Key::Ok
    }

    /// The manifest the kernel loads: one of the two compiled-in boot manifests, never a name
    /// taken from the key.
    pub fn manifest(&self) -> &'static [u8] {
        if self.selftest() {
            crate::services::SELFTEST_MANIFEST
        } else {
            crate::services::SYSTEM_MANIFEST
        }
    }
}

/// The fields of the `kernel|boot_mode|…` line:
/// `mode=<selftest|interactive>|source=<fw_cfg|none>|key=<ok|absent|invalid>|hv=<0|1>`.
impl fmt::Display for BootMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mode, source) = if self.selftest() {
            ("selftest", "fw_cfg")
        } else {
            ("interactive", "none")
        };
        let key = match self.key {
            Key::Ok => "ok",
            Key::Absent => "absent",
            Key::Invalid => "invalid",
        };
        write!(
            f,
            "mode={}|source={}|key={}|hv={}",
            mode,
            source,
            key,
            u8::from(self.hv)
        )
    }
}

/// The key's verdict from what was read: `None` is an absent file; only the single byte `1`
/// is `Ok`.
fn key_of(read: Option<&[u8]>) -> Key {
    match read {
        None => Key::Absent,
        Some(b"1") => Key::Ok,
        Some(_) => Key::Invalid,
    }
}

/// Decides the boot mode. Without the hypervisor bit no fw_cfg port is touched.
pub fn select() -> BootMode {
    let hv = fwcfg::hypervisor_present();
    if !hv {
        return BootMode {
            hv,
            key: Key::Absent,
        };
    }
    // Two bytes: a file of `1` followed by anything reads back as two bytes and is invalid.
    let mut buf = [0u8; 2];
    let key = match fwcfg::read_file(SELFTEST_KEY, &mut buf) {
        Some(n) => key_of(Some(&buf[..n])),
        None => key_of(None),
    };
    BootMode { hv, key }
}
