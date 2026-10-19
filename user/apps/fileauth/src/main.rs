//! fileauth (WP-44, TST-M5-FILE-AUTHORITY): the system-files authority (files.md v1.3) seen
//! from an ordinary process. With no initial handle every read and every change under /SYSTEM
//! is refused with ERR_ACCESS — whatever the spelling of the path — the fonts stay readable but
//! not writable, a non-program under /SYSTEM cannot be started, and the rest of the volume
//! works as before: exit 0x44. Given a read-only SystemFiles handle (its bootstrap handle) it
//! reads /SYSTEM but still changes nothing there: exit 0x45. Else the failing step.

#![no_std]
#![no_main]

use libnawah::*;

libnawah::entry!(main);

fn refused(r: Result<Handle, i64>) -> bool {
    r == Err(ERR_ACCESS)
}

/// What no authority, and READ alone, both refuse: every change under /SYSTEM.
fn changes_refused() -> Option<u64> {
    if !refused(open(b"/SYSTEM/INPUTD.ELF", O_WRITE)) {
        return Some(20);
    }
    if !refused(open(b"/SYSTEM/NEW.TXT", O_READ | O_WRITE | O_CREATE)) {
        return Some(21);
    }
    if !refused(open(b"/SYSTEM/USERS.DB", O_READ | O_TRUNCATE)) {
        return Some(22);
    }
    if unlink(b"/SYSTEM/SVC-AUTH.TXT") != ERR_ACCESS {
        return Some(23);
    }
    if !refused(open(b"/SYSTEM/FONTS/NOTOSANS.TTF", O_WRITE)) {
        return Some(24);
    }
    if unlink(b"/SYSTEM/FONTS/NOTOSANS.TTF") != ERR_ACCESS {
        return Some(25);
    }
    None
}

fn main() -> u64 {
    let h = bootstrap_handle();
    let reader = h != 0 && handle_type(h) == object_type::SYSTEM_FILES;
    if let Some(step) = changes_refused() {
        return step;
    }
    // The fonts are readable by anyone (the sign-in screen's text); a byte is enough.
    let mut b = [0u8; 4];
    match open(b"/SYSTEM/FONTS/NOTOSANS.TTF", O_READ) {
        Ok(f) => {
            let n = read(f, &mut b);
            handle_close(f);
            if n != Ok(4) {
                return 30;
            }
        }
        Err(_) => return 31,
    }
    // The rest of the volume needs no authority.
    match open(b"/FAUTH.TXT", O_READ | O_WRITE | O_CREATE) {
        Ok(f) => {
            let n = write(f, b"x");
            handle_close(f);
            if n != Ok(1) || unlink(b"/FAUTH.TXT") != 0 {
                return 32;
            }
        }
        Err(_) => return 33,
    }
    if reader {
        // READ: /SYSTEM can be read and listed (the bytes are not printed).
        let mut l = [0u8; 512];
        if dir_list(b"/SYSTEM", &mut l).is_err() {
            return 40;
        }
        if stat(b"/SYSTEM/USERS.DB").is_err() {
            return 41;
        }
        match open(b"/SYSTEM/USERS.DB", O_READ) {
            Ok(f) => {
                let n = read(f, &mut b);
                handle_close(f);
                if n != Ok(4) {
                    return 42;
                }
            }
            Err(_) => return 43,
        }
        return 0x45;
    }
    // No authority: reading /SYSTEM is refused however the path is spelled.
    if !refused(open(b"/SYSTEM/USERS.DB", O_READ)) {
        return 1;
    }
    if !refused(open(b"/system/users.db", O_READ)) {
        return 2;
    }
    if !refused(open(b"/SYSTEM./USERS.DB", O_READ)) {
        return 3;
    }
    if stat(b"/SYSTEM/USERS.DB").map(|_| ()) != Err(ERR_ACCESS) {
        return 4;
    }
    let mut l = [0u8; 512];
    if dir_list(b"/SYSTEM", &mut l) != Err(ERR_ACCESS) {
        return 5;
    }
    // A non-program under /SYSTEM cannot be started (spawn would read it).
    if !refused(process_spawn(b"/SYSTEM/USERS.DB", &[])) {
        return 6;
    }
    // A malformed path keeps its own error.
    if !matches!(open(b"SYSTEM/USERS.DB", O_READ), Err(ERR_BAD_PATH)) {
        return 7;
    }
    0x44
}
