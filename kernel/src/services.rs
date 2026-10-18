//! The kernel's side of the service manager (WP-24, docs/contracts/services.md §1): starts
//! `/SYSTEM/SVCMGR.ELF` as the first process with a control channel, sends it `LOAD <manifest>`
//! and keeps the control endpoint (the diagnostic shell of WP-30 talks through it). The test
//! kernel starts managers of its own with the same functions.

#[cfg(not(feature = "ktest"))]
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::object::channel::{self, ChannelError, Endpoint, Message};
use crate::object::handle::Entry;
use crate::object::process::ProcessObject;
use crate::object::{Object, Rights};
use crate::sched;
#[cfg(not(feature = "ktest"))]
use crate::sync::IrqSpinLock;

pub const MANAGER_IMAGE: &[u8] = b"/SYSTEM/SVCMGR.ELF";
#[cfg(not(feature = "ktest"))]
pub const LAB_MANIFEST: &[u8] = b"/SYSTEM/SERVICES.TXT";
/// Largest reply the kernel accepts from the manager (a `LIST` of 16 services fits).
pub const REPLY_MAX: usize = 4096;

/// A running manager: its process, its waitable object and our end of the control channel.
pub struct Manager {
    #[allow(dead_code)]
    pub pid: u32,
    /// Its exit (the test kernel reads it after closing the control channel).
    #[allow(dead_code)]
    pub object: Arc<ProcessObject>,
    pub ctl: Arc<Endpoint>,
}

#[cfg(not(feature = "ktest"))]
static BOOT_MANAGER: IrqSpinLock<Option<Manager>> = IrqSpinLock::new("svcmgr", None);

/// Loads the manager image from the volume and starts it with the far end of a fresh control
/// channel as its bootstrap handle and a fresh token authority as its second initial handle
/// (auth.md §1: the manager hands the authority to the `auth` service alone); the near end of
/// the channel comes back in the `Manager`.
pub fn spawn_manager() -> Result<Manager, &'static str> {
    let image = crate::loader::read_image(MANAGER_IMAGE).map_err(|e| e.code())?;
    let (ours, theirs) = channel::create();
    let object = Arc::new(ProcessObject::new());
    let initial = alloc::vec![
        Entry {
            object: Object::Channel(theirs),
            rights: Rights::CHANNEL_DEFAULT,
        },
        Entry {
            object: Object::Authority(Arc::new(crate::object::token::Authority::new())),
            rights: Rights::AUTHORITY_DEFAULT,
        },
    ];
    let pid =
        crate::user::spawn_elf_with(&image, 1, initial, object.clone()).map_err(|e| e.code())?;
    kprintln!(
        "OSX|{}|kernel|spawn|pid={}|path={}|handles=2|by=kernel",
        crate::BUILD_ID,
        pid,
        core::str::from_utf8(MANAGER_IMAGE).unwrap_or("?")
    );
    Ok(Manager {
        pid,
        object,
        ctl: ours,
    })
}

/// Sends `req` on the control channel and waits for the reply until `deadline` (ticks).
pub fn request(ctl: &Endpoint, req: &[u8], deadline: u64) -> Result<Vec<u8>, &'static str> {
    request_with(ctl, req, Vec::new(), deadline).map(|m| m.bytes)
}

/// `request` with handles attached to the request; the whole reply (with any handle it
/// carries, such as a client endpoint from `CONNECT` or a token from `auth`) comes back.
pub fn request_with(
    ctl: &Endpoint,
    req: &[u8],
    handles: Vec<Entry>,
    deadline: u64,
) -> Result<Message, &'static str> {
    ctl.write(Message {
        bytes: req.to_vec(),
        handles,
    })
    .map_err(|_| "K_E_SVC_WRITE")?;
    let mut reply: Option<Result<Message, &'static str>> = None;
    sched::poll_until(deadline, || {
        match ctl.read(REPLY_MAX, 4, None) {
            Ok(m) => reply = Some(Ok(m)),
            Err(ChannelError::ShouldWait) => {}
            Err(ChannelError::PeerClosed) => reply = Some(Err("K_E_SVC_PEER_CLOSED")),
            Err(ChannelError::BufferTooSmall { .. }) => reply = Some(Err("K_E_SVC_REPLY_SIZE")),
        }
        reply.is_some()
    });
    reply.unwrap_or(Err("K_E_SVC_TIMEOUT"))
}

/// Boot (release kernel, ADR-0016 §1): the manager is the first process; the lab manifest is
/// loaded and its reply reported. The fields of the `kernel|svcmgr|…` line.
#[cfg(not(feature = "ktest"))]
pub fn start_at_boot(timeout_ticks: u64) -> String {
    let t0 = sched::ticks();
    let (pid, reply, code) = match spawn_manager() {
        Ok(m) => {
            let r = request(&m.ctl, &load_request(LAB_MANIFEST), t0 + timeout_ticks);
            let pid = m.pid;
            *BOOT_MANAGER.lock() = Some(m);
            match r {
                Ok(bytes) => (pid, String::from_utf8_lossy(&bytes).into_owned(), "ok"),
                Err(e) => (pid, String::new(), e),
            }
        }
        Err(e) => (0, String::new(), e),
    };
    let waited = sched::ticks() - t0;
    let ok = code == "ok" && reply.starts_with("OK ");
    alloc::format!(
        "pid={}|image={}|manifest={}|reply={}|code={}|selfcheck={}|wait_ticks={}",
        pid,
        core::str::from_utf8(MANAGER_IMAGE).unwrap_or("?"),
        core::str::from_utf8(LAB_MANIFEST).unwrap_or("?"),
        reply.replace('\n', ";"),
        code,
        u8::from(ok),
        waited
    )
}

pub fn load_request(manifest: &[u8]) -> Vec<u8> {
    let mut v = b"LOAD ".to_vec();
    v.extend_from_slice(manifest);
    v
}
