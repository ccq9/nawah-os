//! Session tokens and the authority that mints them (WP-25, docs/contracts/auth.md §1,
//! ADR-0016 §3): a token names a user (uid, gid, permissions) and an expiry; the service that
//! checks authority reads it with `token_info`. Only a holder of an `Authority` object can
//! mint tokens, and only a token handle with the WRITE right can revoke one.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static LIVE_TOKENS: AtomicU32 = AtomicU32::new(0);
static LIVE_AUTHORITIES: AtomicU32 = AtomicU32::new(0);
static LIVE_SYSTEM_FILES: AtomicU32 = AtomicU32::new(0);
/// Token identities: every token minted gets the next number, so a service can tell two
/// handles to the same token apart from handles to different tokens.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn live_tokens() -> u32 {
    LIVE_TOKENS.load(Ordering::Relaxed)
}

pub fn live_authorities() -> u32 {
    LIVE_AUTHORITIES.load(Ordering::Relaxed)
}

/// System-files authorities alive (WP-44; leak checks).
pub fn live_system_files() -> u32 {
    LIVE_SYSTEM_FILES.load(Ordering::Relaxed)
}

/// Permission bits carried by a token (auth.md §1).
pub const PERM_ADMIN: u32 = 1;
pub const PERM_CONFIG_WRITE: u32 = 2;
pub const PERM_NET: u32 = 4;
pub const PERM_SHELL: u32 = 8;
pub const PERM_ALL: u32 = PERM_ADMIN | PERM_CONFIG_WRITE | PERM_NET | PERM_SHELL;

/// `token_info` flags.
pub const FLAG_REVOKED: u32 = 1;
pub const FLAG_EXPIRED: u32 = 2;

pub struct Token {
    pub id: u64,
    pub uid: u32,
    pub gid: u32,
    pub perms: u32,
    /// Tick after which the token is expired; 0 = never.
    pub expires: u64,
    revoked: AtomicBool,
}

impl Token {
    pub fn new(uid: u32, gid: u32, perms: u32, expires: u64) -> Self {
        LIVE_TOKENS.fetch_add(1, Ordering::Relaxed);
        Token {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            uid,
            gid,
            perms,
            expires,
            revoked: AtomicBool::new(false),
        }
    }

    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub fn revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub fn expired(&self, now: u64) -> bool {
        self.expires != 0 && now >= self.expires
    }

    /// The flags word of `token_info` at `now`.
    pub fn flags(&self, now: u64) -> u32 {
        (if self.revoked() { FLAG_REVOKED } else { 0 })
            | (if self.expired(now) { FLAG_EXPIRED } else { 0 })
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        LIVE_TOKENS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The capability to mint tokens: created once at boot for the service manager, which hands
/// it to the `auth` service (services.md §4).
pub struct Authority(());

impl Authority {
    pub fn new() -> Self {
        LIVE_AUTHORITIES.fetch_add(1, Ordering::Relaxed);
        Authority(())
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        LIVE_AUTHORITIES.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The capability over /SYSTEM (WP-44, files.md v1.3): created once at boot for the service
/// manager, which hands narrowed copies to the system services that need them (READ to `auth`,
/// READ|WRITE to `config`). Its rights, not the process, decide: READ reads under /SYSTEM,
/// WRITE changes it.
pub struct SystemFiles(());

impl SystemFiles {
    pub fn new() -> Self {
        LIVE_SYSTEM_FILES.fetch_add(1, Ordering::Relaxed);
        SystemFiles(())
    }
}

impl Default for SystemFiles {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SystemFiles {
    fn drop(&mut self) {
        LIVE_SYSTEM_FILES.fetch_sub(1, Ordering::Relaxed);
    }
}
