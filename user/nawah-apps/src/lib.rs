//! nawah-apps — the application registry's entry parser (apps.md v1, ADR-0023, WP-100).
//! `#![no_std]`, no allocation, no dependencies: an entry borrows from the file's bytes. The
//! bytes are untrusted (a registry file is read by the service manager, WP-101): every loop is
//! bounded by the file (at most FILE_MAX bytes), nothing indexes or slices by a computed
//! position that can fail, and every refusal is an [`Error`] with its contract name. The
//! checks run in the order apps.md §5 states, so one file always gets one error.

#![cfg_attr(not(test), no_std)]

/// Largest entry file (apps.md §2).
pub const FILE_MAX: usize = 1024;
/// Most entries in one registry (apps.md §4).
pub const MAX_APPS: usize = 16;
/// Longest id (apps.md §2: the 8.3 base of `<ID>.APP`).
pub const ID_MAX: usize = 8;
/// Most bytes of a display name's UTF-8 (apps.md §2): display's TITLE_MAX counts bytes
/// (user/apps/displayd/src/main.rs `title: [u8; TITLE_MAX]`), so a name is never cut as a title.
pub const NAME_MAX_BYTES: usize = 32;
/// Ids no entry may take (apps.md §3).
pub const RESERVED: [&str; 15] = [
    "app", "auth", "config", "desktop", "display", "input", "kernel", "manager", "narrator", "net",
    "session", "sh", "shell", "svcmgr", "system",
];
/// The dependency allow-list (apps.md §2-§3), bit `i` of [`Deps`] is `ALLOWED_DEPS[i]`.
pub const ALLOWED_DEPS: [&str; 3] = ["display", "config", "net"];

/// Why an entry is refused (apps.md §5); [`Error::name`] is the contract's stable name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Truncated,
    BadUtf8,
    ControlByte,
    Syntax,
    UnknownKey,
    DupKey,
    MissingKey,
    BadId,
    ReservedId,
    BadElf,
    BadName,
    BadDeps,
    DepNotAllowed,
    FileName,
    DupId,
    TooMany,
}

impl Error {
    pub const fn name(self) -> &'static str {
        match self {
            Error::TooLarge => "TOO_LARGE",
            Error::Truncated => "TRUNCATED",
            Error::BadUtf8 => "BAD_UTF8",
            Error::ControlByte => "CONTROL_BYTE",
            Error::Syntax => "SYNTAX",
            Error::UnknownKey => "UNKNOWN_KEY",
            Error::DupKey => "DUP_KEY",
            Error::MissingKey => "MISSING_KEY",
            Error::BadId => "BAD_ID",
            Error::ReservedId => "RESERVED_ID",
            Error::BadElf => "BAD_ELF",
            Error::BadName => "BAD_NAME",
            Error::BadDeps => "BAD_DEPS",
            Error::DepNotAllowed => "DEP_NOT_ALLOWED",
            Error::FileName => "FILE_NAME",
            Error::DupId => "DUP_ID",
            Error::TooMany => "TOO_MANY",
        }
    }
}

/// The declared dependencies, a set over [`ALLOWED_DEPS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Deps(u8);

impl Deps {
    pub const fn bits(self) -> u8 {
        self.0
    }
    /// Whether `name` is declared.
    pub fn contains(self, name: &str) -> bool {
        ALLOWED_DEPS
            .iter()
            .zip(0u8..)
            .any(|(d, i)| *d == name && self.0 & (1 << i) != 0)
    }
}

/// One accepted entry, borrowed from its file's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct App<'a> {
    pub id: &'a str,
    pub elf: &'a str,
    pub name_ar: &'a str,
    pub name_en: &'a str,
    pub deps: Deps,
}

/// The five keys of an entry (apps.md §2), in the order their values are checked.
const KEYS: [&str; 5] = ["id", "elf", "name.ar", "name.en", "deps"];
/// The image's directory and extension (apps.md §2, ADR-0023 item 3).
const ELF_DIR: &str = "/SYSTEM/APPS/";
const ELF_EXT: &str = ".ELF";

/// Parses one entry file (apps.md §2-§3, §5).
pub fn parse(bytes: &[u8]) -> Result<App<'_>, Error> {
    if bytes.len() > FILE_MAX {
        return Err(Error::TooLarge);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(Error::Truncated);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| Error::BadUtf8)?;
    if bytes.iter().any(|&b| (b < 0x20 && b != b'\n') || b == 0x7f) {
        return Err(Error::ControlByte);
    }
    let body = text.strip_suffix('\n').ok_or(Error::Truncated)?;
    let mut vals: [Option<&str>; 5] = [None; 5];
    for line in body.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = line.split_once('=').ok_or(Error::Syntax)?;
        let slot = KEYS
            .iter()
            .position(|k| *k == key)
            .and_then(|i| vals.get_mut(i))
            .ok_or(Error::UnknownKey)?;
        if slot.is_some() {
            return Err(Error::DupKey);
        }
        *slot = Some(val);
    }
    let [Some(id), Some(elf), Some(name_ar), Some(name_en), Some(deps)] = vals else {
        return Err(Error::MissingKey);
    };
    if !id_ok(id) {
        return Err(Error::BadId);
    }
    if RESERVED.contains(&id) {
        return Err(Error::ReservedId);
    }
    if !elf_ok(elf) {
        return Err(Error::BadElf);
    }
    if !name_ok(name_ar) || !name_ok(name_en) {
        return Err(Error::BadName);
    }
    let deps = parse_deps(deps)?;
    Ok(App {
        id,
        elf,
        name_ar,
        name_en,
        deps,
    })
}

/// `[a-z][a-z0-9]{0,7}` (apps.md §2).
fn id_ok(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() <= ID_MAX
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `/SYSTEM/APPS/` + an 8.3 base of `[A-Z0-9_]{1,8}` + `.ELF`, exactly (apps.md §2).
fn elf_ok(elf: &str) -> bool {
    match elf
        .strip_prefix(ELF_DIR)
        .and_then(|r| r.strip_suffix(ELF_EXT))
    {
        Some(base) => {
            (1..=8).contains(&base.len())
                && base
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        }
        None => false,
    }
}

/// A character no display name may hold anywhere (apps.md §2): the separators `#` and `=`, the
/// C1 controls, the zero-width space and joiners, the direction marks, the line and paragraph
/// separators, the embeddings, overrides and isolates, and the byte order mark.
fn forbidden_in_name(c: char) -> bool {
    matches!(c,
        '#' | '=' | '\u{80}'..='\u{9f}' | '\u{61c}' | '\u{200b}'..='\u{200f}'
        | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        | '\u{feff}')
}

/// The white space no display name may start or end with (apps.md §2): Unicode White_Space
/// less the control bytes and the code points [`forbidden_in_name`] refuses anywhere.
fn edge_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// 1-32 bytes, no white space first or last, nothing [`forbidden_in_name`] (apps.md §2).
fn name_ok(name: &str) -> bool {
    (1..=NAME_MAX_BYTES).contains(&name.len())
        && !name.starts_with(edge_space)
        && !name.ends_with(edge_space)
        && !name.chars().any(forbidden_in_name)
}

/// `-`, or names of the allow-list separated by `,` with no empty item and no repeat; each item
/// is checked in order: its letters (BAD_DEPS), the allow-list (DEP_NOT_ALLOWED), a repeat
/// (BAD_DEPS).
fn parse_deps(deps: &str) -> Result<Deps, Error> {
    if deps == "-" {
        return Ok(Deps(0));
    }
    let mut bits = 0u8;
    for d in deps.split(',') {
        if d.is_empty() || !d.bytes().all(|c| c.is_ascii_lowercase()) {
            return Err(Error::BadDeps);
        }
        let bit = ALLOWED_DEPS
            .iter()
            .position(|a| *a == d)
            .and_then(|i| 1u8.checked_shl(u32::try_from(i).ok()?))
            .ok_or(Error::DepNotAllowed)?;
        if bits & bit != 0 {
            return Err(Error::BadDeps);
        }
        bits |= bit;
    }
    Ok(Deps(bits))
}

/// Whether `file` (a bare name as the directory lists it) is `<ID>.APP` for `id`, compared as
/// the volume resolves short names (ASCII case folded).
pub fn check_file_name(file: &[u8], id: &str) -> Result<(), Error> {
    match file.split_at_checked(id.len()) {
        Some((base, ext))
            if base.eq_ignore_ascii_case(id.as_bytes()) && ext.eq_ignore_ascii_case(b".APP") =>
        {
            Ok(())
        }
        _ => Err(Error::FileName),
    }
}

/// A set of accepted entries (apps.md §4).
pub struct Registry<'a> {
    apps: [Option<App<'a>>; MAX_APPS],
    n: usize,
}

impl<'a> Default for Registry<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Registry<'a> {
    pub const fn new() -> Self {
        Registry {
            apps: [None; MAX_APPS],
            n: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn get(&self, i: usize) -> Option<&App<'a>> {
        self.apps.get(i).and_then(|a| a.as_ref())
    }
    pub fn find(&self, id: &str) -> Option<&App<'a>> {
        self.apps.iter().flatten().find(|a| a.id == id)
    }
    /// Parses `bytes` as the entry file `file` and adds it (apps.md §4: the entry, then its file
    /// name, then a repeated id, then the capacity); a refused entry changes nothing.
    pub fn add(&mut self, file: &[u8], bytes: &'a [u8]) -> Result<App<'a>, Error> {
        let app = parse(bytes)?;
        check_file_name(file, app.id)?;
        if self.find(app.id).is_some() {
            return Err(Error::DupId);
        }
        let slot = self.apps.get_mut(self.n).ok_or(Error::TooMany)?;
        *slot = Some(app);
        self.n = self.n.saturating_add(1);
        Ok(app)
    }
}
