//! The manager's answer to `END_SESSION` as the session reads it (services.md v1.17 and v1.21,
//! session.md v1.12; WP-178, L-145): `ENDED <n>`, `n` the count in the manager's own decimal form. The
//! session confirms the end of the last session's job on this answer alone, so its form is
//! checked here, apart from the guest cases: no case makes the manager write a malformed one.

use nawah_apps::ended_count;

#[test]
fn the_managers_form_is_taken_with_its_count() {
    for (reply, n) in [
        (&b"ENDED 0"[..], 0u32),
        (b"ENDED 1", 1),
        (b"ENDED 2", 2),
        (b"ENDED 8", 8),
        (b"ENDED 16", 16),
        (b"ENDED 4294967295", u32::MAX),
    ] {
        assert_eq!(
            ended_count(reply),
            Some(n),
            "{:?}",
            core::str::from_utf8(reply)
        );
    }
}

#[test]
fn every_count_the_manager_writes_is_read_back() {
    // The manager writes the count with no sign, no padding and no leading zero
    // (user/apps/svcmgr/src/main.rs `Out::num`); `format!` writes the same form.
    for n in (0u32..=4096).chain([65_535, 65_536, 999_999_999, 1_000_000_000, u32::MAX - 1]) {
        let reply = format!("ENDED {n}");
        assert_eq!(ended_count(reply.as_bytes()), Some(n), "{reply}");
    }
}

#[test]
fn anything_but_the_managers_form_is_refused() {
    let refused: [&[u8]; 34] = [
        b"",
        b"ENDED",
        b"ENDED ",
        b"ENDED  ",
        b"ENDED x",
        b"ENDED 2x",
        b"ENDED x2",
        b"ENDED 2 ",
        b"ENDED  2",
        b"ENDED 2 3",
        b"ENDED 2\n",
        b"ENDED 2\0",
        b"ENDED\t2",
        b"ENDED2",
        b"ENDED -1",
        b"ENDED +1",
        b"ENDED 00",
        b"ENDED 02",
        b"ENDED 0x2",
        b"ENDED 2.0",
        b"ENDED 4294967296",
        b"ENDED 99999999999999999999",
        b"ended 2",
        b"Ended 2",
        b" ENDED 2",
        b"XENDED 2",
        b"ENDED: 2",
        b"ENDING 2",
        b"OK",
        b"BEGUN",
        b"ERR ACCESS",
        b"OK app:deaf#1",
        "ENDED \u{0662}".as_bytes(),
        b"ENDED \xff",
    ];
    for reply in refused {
        assert_eq!(ended_count(reply), None, "{:?}", reply);
    }
}
