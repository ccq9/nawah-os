//! TST-M6-APP-REGISTRY-FUZZ (WP-100, apps.md v1, ADR-0023): the application registry's entry
//! parser on the host. Hand-written malformed entries are refused by their contract name; a
//! seeded, deterministic corpus (a PRNG of the test's own: builds are --offline) of generated
//! malformed entries in every class is refused by name; mutated well-formed entries never make
//! the parser panic and get exactly the verdict of a reference model of apps.md written here
//! with std and with its own literal lists (reserved ids, allowed dependencies, forbidden and
//! edge characters), which a separate test holds equal to apps.md §3 and to the crate's; the well-formed examples and the repository's sample entries
//! (platform/pc-qemu/apps/*.APP) are accepted with their fields exactly.

use nawah_apps::*;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

// ---- a small deterministic PRNG (xorshift64*), seeded per test --------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

// ---- the reference model: apps.md v1 §2-§5 written plainly with std ---------------------------

/// Pieces spliced into mutated entries (a key line, a denied dependency, a lone lead byte...).
const PIECES: [&[u8]; 7] = [
    b"id=notes\n",
    b"deps=auth\n",
    b"elf=/SYSTEM/APPS/Y.ELF\n",
    b"\xd9",
    b"\r\n",
    b"name.en=",
    b"#",
];

/// The model's own lists, written from apps.md §2-§3, never taken from the crate.
const MODEL_RESERVED: [&str; 15] = [
    "app", "auth", "config", "desktop", "display", "input", "kernel", "manager", "narrator", "net",
    "session", "sh", "shell", "svcmgr", "system",
];
const MODEL_ALLOWED: [&str; 3] = ["display", "config", "net"];
/// apps.md §2: code points no display name may hold anywhere (besides `=`).
const MODEL_FORBIDDEN: [(char, char); 8] = [
    ('\u{80}', '\u{9f}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{2028}', '\u{2029}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2066}', '\u{2069}'),
    ('\u{feff}', '\u{feff}'),
    ('#', '#'),
];
/// apps.md §2: the white space no display name may start or end with (Unicode White_Space
/// outside the control bytes and the code points forbidden anywhere).
const MODEL_EDGE_SPACE: [char; 17] = [
    ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];

const KEYS: [&str; 5] = ["id", "elf", "name.ar", "name.en", "deps"];

#[derive(Debug, PartialEq, Eq)]
struct Fields {
    id: String,
    elf: String,
    name_ar: String,
    name_en: String,
    deps: Vec<String>,
}

fn model_name(v: &str) -> bool {
    (1..=32).contains(&v.len())
        && !v.starts_with(MODEL_EDGE_SPACE)
        && !v.ends_with(MODEL_EDGE_SPACE)
        && !v.chars().any(|c| {
            c == '='
                || MODEL_FORBIDDEN
                    .iter()
                    .any(|(lo, hi)| (*lo..=*hi).contains(&c))
        })
}

fn model(file: &[u8]) -> Result<Fields, &'static str> {
    if file.len() > 1024 {
        return Err("TOO_LARGE");
    }
    if file.last() != Some(&b'\n') {
        return Err("TRUNCATED");
    }
    let s = std::str::from_utf8(file).map_err(|_| "BAD_UTF8")?;
    if s.bytes().any(|b| (b < 0x20 && b != b'\n') || b == 0x7f) {
        return Err("CONTROL_BYTE");
    }
    let mut map: HashMap<&str, &str> = HashMap::new();
    for line in s[..s.len() - 1].split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or("SYNTAX")?;
        if !KEYS.contains(&k) {
            return Err("UNKNOWN_KEY");
        }
        if map.insert(k, v).is_some() {
            return Err("DUP_KEY");
        }
    }
    if KEYS.iter().any(|k| !map.contains_key(k)) {
        return Err("MISSING_KEY");
    }
    let id = map["id"];
    let id_ok = (1..=8).contains(&id.len())
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !id_ok {
        return Err("BAD_ID");
    }
    if MODEL_RESERVED.contains(&id) {
        return Err("RESERVED_ID");
    }
    let elf = map["elf"];
    let base = elf
        .strip_prefix("/SYSTEM/APPS/")
        .and_then(|r| r.strip_suffix(".ELF"));
    let elf_ok = base.is_some_and(|b| {
        (1..=8).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
    });
    if !elf_ok {
        return Err("BAD_ELF");
    }
    if !model_name(map["name.ar"]) || !model_name(map["name.en"]) {
        return Err("BAD_NAME");
    }
    let mut deps = Vec::new();
    if map["deps"] != "-" {
        for d in map["deps"].split(',') {
            if d.is_empty() || !d.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err("BAD_DEPS");
            }
            if !MODEL_ALLOWED.contains(&d) {
                return Err("DEP_NOT_ALLOWED");
            }
            if deps.iter().any(|x| x == d) {
                return Err("BAD_DEPS");
            }
            deps.push(d.to_string());
        }
    }
    Ok(Fields {
        id: id.into(),
        elf: elf.into(),
        name_ar: map["name.ar"].into(),
        name_en: map["name.en"].into(),
        deps,
    })
}

/// The parser's verdict in the model's terms; a panic is reported with the input.
fn verdict(file: &[u8]) -> Result<Fields, &'static str> {
    let got = catch_unwind(AssertUnwindSafe(|| parse(file)));
    let got = got
        .unwrap_or_else(|_| panic!("the parser panicked on {:?}", String::from_utf8_lossy(file)));
    got.map(|a| {
        let mut deps: Vec<String> = Vec::new();
        for d in MODEL_ALLOWED {
            if a.deps.contains(d) {
                deps.push(d.to_string());
            }
        }
        Fields {
            id: a.id.into(),
            elf: a.elf.into(),
            name_ar: a.name_ar.into(),
            name_en: a.name_en.into(),
            deps,
        }
    })
    .map_err(Error::name)
}

fn sorted(mut f: Fields) -> Fields {
    f.deps.sort();
    f
}

// ---- building entries --------------------------------------------------------------------------

fn entry(id: &str, elf: &str, ar: &str, en: &str, deps: &str) -> Vec<u8> {
    format!("id={id}\nelf={elf}\nname.ar={ar}\nname.en={en}\ndeps={deps}\n").into_bytes()
}

fn good() -> Vec<u8> {
    entry(
        "notes",
        "/SYSTEM/APPS/NOTES.ELF",
        "الملاحظات",
        "Notes",
        "display,config",
    )
}

fn err(file: &[u8]) -> &'static str {
    match verdict(file) {
        Ok(f) => panic!("accepted {:?} as {f:?}", String::from_utf8_lossy(file)),
        Err(e) => e,
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---- the tests ---------------------------------------------------------------------------------

#[test]
fn well_formed_examples_are_accepted_exactly() {
    let a = good();
    let app = parse(&a).expect("the basic example");
    assert_eq!(app.id, "notes");
    assert_eq!(app.elf, "/SYSTEM/APPS/NOTES.ELF");
    assert_eq!(app.name_ar, "الملاحظات");
    assert_eq!(app.name_en, "Notes");
    assert!(
        app.deps.contains("display") && app.deps.contains("config") && !app.deps.contains("net")
    );
    assert!(!app.deps.contains("auth") && !app.deps.contains("session"));

    // No dependency, the longest id, a 16-letter Arabic name of 32 bytes (the limit is in bytes:
    // display's TITLE_MAX), digits, the underscore in the image's base, comments and blank
    // lines, keys in another order.
    let ar32 = "الملاحظاتاليومية";
    assert_eq!((ar32.chars().count(), ar32.len()), (16, 32));
    let b = format!(
        "# comment\n\ndeps=-\nname.en=Text Editor 2\n#another=comment\nelf=/SYSTEM/APPS/T_EDIT9.ELF\nname.ar={ar32}\nid=texted99\n\n"
    );
    let app = parse(b.as_bytes()).expect("the reordered example");
    assert_eq!((app.id, app.elf), ("texted99", "/SYSTEM/APPS/T_EDIT9.ELF"));
    assert_eq!((app.name_ar, app.name_en), (ar32, "Text Editor 2"));
    assert_eq!(app.deps.bits(), 0);
    for d in ALLOWED_DEPS {
        assert!(!app.deps.contains(d));
    }

    // Every allowed dependency, in any order; a one-letter id; a one-character name.
    let c = entry("a", "/SYSTEM/APPS/A.ELF", "ع", "A", "net,config,display");
    let app = parse(&c).expect("all three dependencies");
    assert_eq!((app.id, app.name_ar, app.name_en), ("a", "ع", "A"));
    assert!(ALLOWED_DEPS.iter().all(|d| app.deps.contains(d)));

    // The largest file accepted is FILE_MAX bytes exactly.
    let mut big = good();
    let pad = FILE_MAX - big.len() - 2;
    big.extend(b"#");
    big.extend(std::iter::repeat_n(b'x', pad));
    big.extend(b"\n");
    assert_eq!(big.len(), FILE_MAX);
    assert_eq!(parse(&big).map(|a| a.id), Ok("notes"));
    // A Latin name of 32 bytes; an inner space, no-break space or ideographic space is not at
    // an edge.
    let en32 = "Text Editor For Daily Notes 1234";
    assert_eq!(en32.len(), 32);
    let d = entry("ed", "/SYSTEM/APPS/ED.ELF", "محرر النصوص", en32, "display");
    let app = parse(&d).expect("a 32-byte Latin name");
    assert_eq!((app.name_ar, app.name_en), ("محرر النصوص", en32));
    let e = entry(
        "ed",
        "/SYSTEM/APPS/ED.ELF",
        "محرر\u{a0}النصوص",
        "Text\u{3000}Editor",
        "-",
    );
    let app = parse(&e).expect("inner white space");
    assert_eq!(
        (app.name_ar, app.name_en),
        ("محرر\u{a0}النصوص", "Text\u{3000}Editor")
    );
    for f in [&a[..], b.as_bytes(), &c, &big, &d, &e] {
        assert_eq!(
            verdict(f).map(sorted),
            model(f).map(sorted),
            "parser and model differ"
        );
    }
}

#[test]
fn repository_samples_parse_and_register() {
    let dir = root().join("platform/pc-qemu/apps");
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("platform/pc-qemu/apps")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "APP"))
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&p).expect("read"))
        })
        .collect();
    files.sort();
    assert!(files.len() >= 2, "the repository carries sample entries");
    let mut reg = Registry::new();
    for (name, bytes) in &files {
        let app = reg
            .add(name.as_bytes(), bytes)
            .unwrap_or_else(|e| panic!("{name}: {}", e.name()));
        assert_eq!(
            Ok(sorted(verdict(bytes).unwrap())),
            model(bytes).map(sorted)
        );
        assert_eq!(format!("{}.APP", app.id.to_ascii_uppercase()), *name);
        assert!(!app.deps.contains("auth") && !app.deps.contains("session"));
    }
    assert_eq!(reg.len(), files.len());
    let notes = reg.find("notes").expect("NOTES.APP");
    assert_eq!((notes.name_ar, notes.name_en), ("الملاحظات", "Notes"));
}

#[test]
fn every_service_of_the_system_manifest_is_a_reserved_id() {
    let manifest = std::fs::read_to_string(root().join("platform/pc-qemu/manifests/services.txt"))
        .expect("services.txt");
    let mut names = 0;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("");
        let Some(name) = line.split(' ').find(|f| !f.is_empty()) else {
            continue;
        };
        names += 1;
        let file = entry(name, "/SYSTEM/APPS/X.ELF", "اسم", "Name", "-");
        let e = err(&file);
        assert!(
            e == "RESERVED_ID" || (name.len() > ID_MAX && e == "BAD_ID"),
            "service {name} usable as an application id ({e})"
        );
    }
    assert!(names >= 8, "the manifest's services were read ({names})");
    for id in MODEL_RESERVED
        .iter()
        .chain(["desktop", "session", "narrator", "auth"].iter())
    {
        let file = entry(id, "/SYSTEM/APPS/X.ELF", "اسم", "Name", "-");
        assert_eq!(err(&file), "RESERVED_ID", "{id}");
    }
}

#[test]
fn malformed_entries_are_refused_by_name() {
    let g = String::from_utf8(good()).unwrap();
    let swap = |from: &str, to: &str| g.replacen(from, to, 1).into_bytes();
    let mut cases: Vec<(Vec<u8>, &str)> = vec![
        (vec![], "TRUNCATED"),
        (g.trim_end().as_bytes().to_vec(), "TRUNCATED"),
        (g.as_bytes()[..g.len() / 2].to_vec(), "TRUNCATED"),
        (vec![b'\n'; FILE_MAX + 1], "TOO_LARGE"),
        (vec![b'#'; 1 << 20], "TOO_LARGE"),
        (g.replace('\n', "\r\n").into_bytes(), "CONTROL_BYTE"),
        (swap("Notes\n", "Notes\r\n"), "CONTROL_BYTE"),
        (g.replace('\n', "\r").into_bytes(), "TRUNCATED"),
        (swap("Notes", "No\ttes"), "CONTROL_BYTE"),
        (swap("Notes", "No\0tes"), "CONTROL_BYTE"),
        (swap("Notes", "No\x7ftes"), "CONTROL_BYTE"),
        (swap("Notes", "No\x1btes"), "CONTROL_BYTE"),
        (
            [&g.as_bytes()[..g.len() - 1], b"\xff\n"].concat(),
            "BAD_UTF8",
        ),
        (
            g.replacen("الملاحظات", "\u{0627}", 1)
                .into_bytes()
                .iter()
                .map(|&b| if b == 0xa7 { 0x27 } else { b })
                .collect(),
            "BAD_UTF8",
        ),
        (swap("deps=display,config", "deps display,config"), "SYNTAX"),
        (format!("{g}junk\n").into_bytes(), "SYNTAX"),
        (format!("{g} #comment\n").into_bytes(), "SYNTAX"),
        (swap("id=", "ID="), "UNKNOWN_KEY"),
        (swap("id=", " id="), "UNKNOWN_KEY"),
        (swap("id=", "id ="), "UNKNOWN_KEY"),
        (format!("{g}icon=x\n").into_bytes(), "UNKNOWN_KEY"),
        (format!("{g}=x\n").into_bytes(), "UNKNOWN_KEY"),
        (format!("{g}id=notes\n").into_bytes(), "DUP_KEY"),
        (
            format!("{g}elf=/SYSTEM/APPS/NOTES.ELF\n").into_bytes(),
            "DUP_KEY",
        ),
        (swap("elf=/SYSTEM/APPS/NOTES.ELF\n", ""), "MISSING_KEY"),
        (swap("id=notes\n", ""), "MISSING_KEY"),
        (swap("name.ar=الملاحظات\n", ""), "MISSING_KEY"),
        (swap("name.en=Notes\n", ""), "MISSING_KEY"),
        (swap("deps=display,config\n", ""), "MISSING_KEY"),
        (
            swap(
                "elf=/SYSTEM/APPS/NOTES.ELF\n",
                "#elf=/SYSTEM/APPS/NOTES.ELF\n",
            ),
            "MISSING_KEY",
        ),
        (swap("id=notes", "id="), "BAD_ID"),
        (swap("id=notes", "id=notes1234"), "BAD_ID"),
        (swap("id=notes", "id=Notes"), "BAD_ID"),
        (swap("id=notes", "id=1notes"), "BAD_ID"),
        (swap("id=notes", "id=no-tes"), "BAD_ID"),
        (swap("id=notes", "id=no_tes"), "BAD_ID"),
        (swap("id=notes", "id=no tes"), "BAD_ID"),
        (swap("id=notes", "id=notes "), "BAD_ID"),
        (swap("id=notes", "id=no#tes"), "BAD_ID"),
        (swap("id=notes", "id=no=tes"), "BAD_ID"),
        (swap("id=notes", "id=نوتس"), "BAD_ID"),
        (swap("id=notes", "id=session"), "RESERVED_ID"),
        (swap("id=notes", "id=desktop"), "RESERVED_ID"),
        (swap("id=notes", "id=narrator"), "RESERVED_ID"),
        (swap("id=notes", "id=app"), "RESERVED_ID"),
        (swap("NOTES.ELF", "notes.elf"), "BAD_ELF"),
        (swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf="), "BAD_ELF"),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/AUTHD.ELF"),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/APPS/NOTES.ELF"),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/system/apps/NOTES.ELF"),
            "BAD_ELF",
        ),
        (
            swap(
                "elf=/SYSTEM/APPS/NOTES.ELF",
                "elf=/SYSTEM/APPS/../AUTHD.ELF",
            ),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/X/NOTES.ELF"),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/.ELF"),
            "BAD_ELF",
        ),
        (
            swap(
                "elf=/SYSTEM/APPS/NOTES.ELF",
                "elf=/SYSTEM/APPS/NOTESAPP9.ELF",
            ),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/NOTES.EXE"),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/NOTES.ELF "),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/NO#ES.ELF"),
            "BAD_ELF",
        ),
        (
            swap("elf=/SYSTEM/APPS/NOTES.ELF", "elf=/SYSTEM/APPS/NOTES.ELF=X"),
            "BAD_ELF",
        ),
        (swap("name.en=Notes", "name.en="), "BAD_NAME"),
        (swap("name.en=Notes", "name.en= Notes"), "BAD_NAME"),
        (swap("name.en=Notes", "name.en=Notes "), "BAD_NAME"),
        (swap("name.en=Notes", "name.en=No#tes"), "BAD_NAME"),
        (swap("name.en=Notes", "name.en=No=tes"), "BAD_NAME"),
        (
            swap("name.en=Notes", &format!("name.en={}", "N".repeat(33))),
            "BAD_NAME",
        ),
        (
            swap("name.ar=الملاحظات", &format!("name.ar={}", "م".repeat(33))),
            "BAD_NAME",
        ),
        (
            swap("name.ar=الملاحظات", "name.ar=الملا\u{202e}حظات"),
            "BAD_NAME",
        ),
        (
            swap("name.ar=الملاحظات", "name.ar=\u{2067}الملاحظات"),
            "BAD_NAME",
        ),
        (
            swap("name.ar=الملاحظات", "name.ar=الملاحظات\u{200f}"),
            "BAD_NAME",
        ),
        (
            swap("name.ar=الملاحظات", "name.ar=ال\u{61c}ملاحظات"),
            "BAD_NAME",
        ),
        (swap("name.en=Notes", "name.en=No\u{85}tes"), "BAD_NAME"),
        (swap("name.en=Notes", "name.en=No\u{9b}tes"), "BAD_NAME"),
        (swap("deps=display,config", "deps="), "BAD_DEPS"),
        (swap("deps=display,config", "deps=display,"), "BAD_DEPS"),
        (swap("deps=display,config", "deps=,display"), "BAD_DEPS"),
        (
            swap("deps=display,config", "deps=display,,config"),
            "BAD_DEPS",
        ),
        (
            swap("deps=display,config", "deps=display, config"),
            "BAD_DEPS",
        ),
        (
            swap("deps=display,config", "deps=display,display"),
            "BAD_DEPS",
        ),
        (swap("deps=display,config", "deps=Display"), "BAD_DEPS"),
        (swap("deps=display,config", "deps=-,display"), "BAD_DEPS"),
        (swap("deps=display,config", "deps=display#x"), "BAD_DEPS"),
        (swap("deps=display,config", "deps=auth"), "DEP_NOT_ALLOWED"),
        (
            swap("deps=display,config", "deps=display,session"),
            "DEP_NOT_ALLOWED",
        ),
        (swap("deps=display,config", "deps=input"), "DEP_NOT_ALLOWED"),
        (
            swap("deps=display,config", "deps=narrator"),
            "DEP_NOT_ALLOWED",
        ),
        (swap("deps=display,config", "deps=sh"), "DEP_NOT_ALLOWED"),
        (
            swap("deps=display,config", "deps=clipboard"),
            "DEP_NOT_ALLOWED",
        ),
    ];
    // Display names are limited in bytes (32, display's TITLE_MAX): 33 Latin bytes, 17 Arabic
    // letters (34 bytes), 16 Arabic letters and a space (33 bytes).
    let en33 = "Text Editor For Daily Notes 12345";
    let ar17 = "م".repeat(17);
    let ar16s = format!("{} م", "م".repeat(15));
    assert_eq!((en33.len(), ar17.len(), ar16s.len()), (33, 34, 33));
    cases.push((
        swap("name.en=Notes", &format!("name.en={en33}")),
        "BAD_NAME",
    ));
    cases.push((
        swap("name.ar=الملاحظات", &format!("name.ar={ar17}")),
        "BAD_NAME",
    ));
    cases.push((
        swap("name.ar=الملاحظات", &format!("name.ar={ar16s}")),
        "BAD_NAME",
    ));
    // Code points apps.md §2 forbids in a name, each inside a name (20 cases): the C1 range by its
    // two ends alone, every other forbidden code point by itself.
    let forbidden = [
        '\u{80}', '\u{9f}', '\u{61c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}',
        '\u{2028}', '\u{2029}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
        '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}',
    ];
    for c in forbidden {
        cases.push((
            swap("name.en=Notes", &format!("name.en=No{c}tes")),
            "BAD_NAME",
        ));
    }
    // Every white space apps.md §2 forbids at either end of a name (17 x 2 cases).
    let edge = [
        ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{202f}',
        '\u{205f}', '\u{3000}',
    ];
    for c in edge {
        cases.push((
            swap("name.ar=الملاحظات", &format!("name.ar={c}الملاحظات")),
            "BAD_NAME",
        ));
        cases.push((
            swap("name.en=Notes", &format!("name.en=Notes{c}")),
            "BAD_NAME",
        ));
    }
    // The count the oracle states (tools/project.py HOST_SUITES["M6"]).
    assert_eq!(cases.len(), 143, "hand-written cases");
    for (file, want) in &cases {
        assert_eq!(err(file), *want, "{:?}", String::from_utf8_lossy(file));
        assert_eq!(
            model(file).err(),
            Some(*want),
            "the model disagrees on {:?}",
            String::from_utf8_lossy(file)
        );
    }
}

/// One generated malformed entry of each class per round, each with the error apps.md names.
#[test]
fn seeded_generated_malformed_entries_are_refused_by_name() {
    let mut r = Rng::new(0x5EED_0100);
    let lower = b"abcdefghijklmnopqrstuvwxyz";
    let alnum = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for round in 0..2000 {
        let word = |r: &mut Rng, set: &[u8], n: usize| -> String {
            (0..n).map(|_| *r.pick(set) as char).collect()
        };
        // A well-formed base with a random id and image name (the reference model agrees).
        let mut id = word(&mut r, lower, 1);
        let n_id = r.below(8);
        id.push_str(&word(&mut r, alnum, n_id));
        if MODEL_RESERVED.contains(&id.as_str()) {
            continue;
        }
        let elf = format!("/SYSTEM/APPS/{}.ELF", id.to_ascii_uppercase());
        let ok = entry(&id, &elf, "تطبيق", "App", "display");
        assert!(parse(&ok).is_ok(), "round {round}: {id}");
        let cls = round % 14;
        let (file, want): (Vec<u8>, &str) = match cls {
            // an over-long id
            0 => {
                let n = 9 + r.below(40);
                (
                    entry(
                        &format!("a{}", word(&mut r, alnum, n - 1)),
                        &elf,
                        "تطبيق",
                        "App",
                        "-",
                    ),
                    "BAD_ID",
                )
            }
            // a byte outside the id's alphabet at a random place
            1 => {
                let bad = *r.pick(b"-_.:/#= ABCZ\xd9");
                let mut b = id.clone().into_bytes();
                let at = r.below(b.len() + 1);
                b.insert(at, bad);
                let s = String::from_utf8_lossy(&b).into_owned();
                (entry(&s, &elf, "تطبيق", "App", "-"), "BAD_ID")
            }
            // a reserved id
            2 => (
                entry(r.pick(&MODEL_RESERVED), &elf, "تطبيق", "App", "-"),
                "RESERVED_ID",
            ),
            // the image's line missing
            3 => {
                let s = String::from_utf8(ok.clone()).unwrap();
                (
                    s.replace(&format!("elf={elf}\n"), "").into_bytes(),
                    "MISSING_KEY",
                )
            }
            // a key given twice
            4 => {
                let k = *r.pick(&KEYS);
                let s = String::from_utf8(ok.clone()).unwrap();
                let line = s
                    .lines()
                    .find(|l| l.starts_with(&format!("{k}=")))
                    .unwrap()
                    .to_string();
                (format!("{s}{line}\n").into_bytes(), "DUP_KEY")
            }
            // an over-long display name (Arabic or Latin)
            5 => {
                let n = 33 + r.below(60);
                let name: String = std::iter::repeat_n(*r.pick(&['م', 'x', 'ي']), n).collect();
                (entry(&id, &elf, &name, "App", "-"), "BAD_NAME")
            }
            // a name that is not UTF-8 (a lone continuation or lead byte)
            6 => {
                let mut b = ok.clone();
                let at = b.windows(8).position(|w| w == b"name.en=").unwrap() + 8 + r.below(3);
                b.insert(at, *r.pick(&[0x80u8, 0xbf, 0xc3, 0xe2, 0xf0, 0xff]));
                (b, "BAD_UTF8")
            }
            // a control byte anywhere, CR included
            7 => {
                let mut b = ok.clone();
                // before an ASCII byte: a character boundary, so the file stays UTF-8
                let mut at = r.below(b.len());
                while b.get(at).is_some_and(|c| *c >= 0x80) {
                    at += 1;
                }
                let c = *r.pick(&[0u8, 1, 8, 9, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f, 0x7f]);
                b.insert(at, c);
                (b, "CONTROL_BYTE")
            }
            // CR/LF variants of the line ends
            8 => {
                let s = String::from_utf8(ok.clone()).unwrap();
                match r.below(3) {
                    0 => (s.replace('\n', "\r\n").into_bytes(), "CONTROL_BYTE"),
                    1 => (s.replacen('\n', "\n\r", 1).into_bytes(), "CONTROL_BYTE"),
                    _ => (s.replace('\n', "\r").into_bytes(), "TRUNCATED"),
                }
            }
            // `#` or `=` inside a field
            9 => {
                let sep = *r.pick(&["#", "="]);
                match r.below(4) {
                    0 => (
                        entry(&format!("{id}{sep}"), &elf, "تطبيق", "App", "-"),
                        "BAD_ID",
                    ),
                    1 => (
                        entry(&id, &format!("{elf}{sep}"), "تطبيق", "App", "-"),
                        "BAD_ELF",
                    ),
                    2 => (
                        entry(&id, &elf, &format!("تط{sep}بيق"), "App", "-"),
                        "BAD_NAME",
                    ),
                    _ => (
                        entry(&id, &elf, "تطبيق", "App", &format!("display{sep}")),
                        "BAD_DEPS",
                    ),
                }
            }
            // truncated input: cut anywhere before the final LF
            10 => {
                let cut = r.below(ok.len());
                let b = ok[..cut].to_vec();
                (b, "TRUNCATED")
            }
            // huge input
            11 => {
                let mut b = ok.clone();
                let extra = FILE_MAX + 1 - b.len() + r.below(1 << 16);
                b.extend(std::iter::repeat_n(b'#', extra));
                (b, "TOO_LARGE")
            }
            // a denied dependency
            12 => {
                let d = *r.pick(&["auth", "session", "input", "narrator", "sh", "svcmgr"]);
                (
                    entry(&id, &elf, "تطبيق", "App", &format!("display,{d}")),
                    "DEP_NOT_ALLOWED",
                )
            }
            // an image outside /SYSTEM/APPS or not an 8.3 .ELF
            _ => {
                let e = *r.pick(&[
                    "/SYSTEM/AUTHD.ELF",
                    "/SYSTEM/SESSIOND.ELF",
                    "/APPS/X.ELF",
                    "/SYSTEM/APPS/TOOLONGNM.ELF",
                    "/SYSTEM/APPS/X.elf",
                    "/SYSTEM/APPS//X.ELF",
                    "SYSTEM/APPS/X.ELF",
                ]);
                (entry(&id, e, "تطبيق", "App", "-"), "BAD_ELF")
            }
        };
        // Truncation can cut exactly at a line end (the final LF kept): a key then goes missing.
        let want = if cls == 10 && file.last() == Some(&b'\n') {
            "MISSING_KEY"
        } else {
            want
        };
        let got = verdict(&file).err();
        assert_eq!(
            got,
            Some(want),
            "round {round} class {cls}: {:?}",
            String::from_utf8_lossy(&file)
        );
        assert_eq!(
            model(&file).err(),
            Some(want),
            "the model, round {round} class {cls}"
        );
    }
}

/// Mutated well-formed entries: never a panic, and exactly the reference model's verdict.
#[test]
fn seeded_mutations_get_the_reference_models_verdict() {
    let mut r = Rng::new(0xA995_0100);
    let seeds: Vec<Vec<u8>> = vec![
        good(),
        entry("clock", "/SYSTEM/APPS/CLOCK.ELF", "الساعة", "Clock", "display"),
        entry("x1", "/SYSTEM/APPS/X_1.ELF", "س", "X", "-"),
        b"# c\n\ndeps=net\nname.en=A B\nname.ar=\xd8\xa3 \xd8\xa8\nelf=/SYSTEM/APPS/AB.ELF\nid=ab\n".to_vec(),
    ];
    let alphabet: &[u8] = b"\n\r\t\0#=,-_ ./aAzZ09\x7f\x80\xc2\x85\xd8\xa3\xe2\x80\xae\xff";
    let (mut accepted, mut refused) = (0, 0);
    for i in 0..30_000 {
        let mut b = r.pick(&seeds).clone();
        for _ in 0..1 + r.below(4) {
            let len = b.len();
            match r.below(7) {
                0 if len > 0 => {
                    let at = r.below(len);
                    b[at] = *r.pick(alphabet);
                }
                1 => {
                    let at = r.below(len + 1);
                    b.insert(at, *r.pick(alphabet));
                }
                2 if len > 0 => {
                    let at = r.below(len);
                    b.remove(at);
                }
                3 => {
                    let cut = r.below(len + 1);
                    b.truncate(cut);
                }
                4 => {
                    // duplicate a slice (a line, a key) somewhere else
                    let from = r.below(len + 1);
                    let to = (from + r.below(24)).min(len);
                    let piece = b[from..to].to_vec();
                    let at = r.below(len + 1);
                    b.splice(at..at, piece);
                }
                5 => {
                    let at = r.below(len + 1);
                    let piece: &[u8] = r.pick(&PIECES);
                    b.splice(at..at, piece.iter().copied());
                }
                _ => {
                    let at = r.below(len + 1);
                    b.splice(at..at, std::iter::repeat_n(b'm', r.below(1100)));
                }
            }
        }
        let want = model(&b).map(sorted);
        let got = verdict(&b).map(sorted);
        assert_eq!(got, want, "mutation {i}: {:?}", String::from_utf8_lossy(&b));
        if got.is_ok() {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    // The corpus exercises both sides (the counts are the seed's, deterministic).
    assert!(
        accepted > 100 && refused > 10_000,
        "accepted {accepted}, refused {refused}"
    );
}

#[test]
fn the_registry_refuses_duplicates_overflow_and_wrong_file_names() {
    let files: Vec<(String, Vec<u8>)> = (0..MAX_APPS + 1)
        .map(|i| {
            let id = format!("app{i}x");
            let file = format!("{}.APP", id.to_ascii_uppercase());
            (
                file,
                entry(&id, "/SYSTEM/APPS/A.ELF", "تطبيق", "App", "display"),
            )
        })
        .collect();
    let mut reg = Registry::new();
    assert!(reg.is_empty());
    for (name, bytes) in &files[..MAX_APPS] {
        reg.add(name.as_bytes(), bytes)
            .unwrap_or_else(|e| panic!("{name}: {}", e.name()));
    }
    assert_eq!(reg.len(), MAX_APPS);
    let (name, bytes) = &files[MAX_APPS];
    assert_eq!(
        reg.add(name.as_bytes(), bytes).map_err(Error::name),
        Err("TOO_MANY")
    );
    assert_eq!(
        reg.add(b"APP0X.APP", &files[0].1).map_err(Error::name),
        Err("DUP_ID")
    );
    assert_eq!(reg.len(), MAX_APPS);
    assert_eq!(reg.get(0).map(|a| a.id), Some("app0x"));
    assert!(reg.get(MAX_APPS).is_none());

    let mut reg = Registry::new();
    let g = good();
    for wrong in [
        &b"CLOCK.APP"[..],
        b"NOTES.ELF",
        b"NOTES",
        b"NOTES.APP.APP",
        b"NOTE.APP",
        b"NOTESS.APP",
        b"",
        b"/SYSTEM/APPS/NOTES.APP",
        b"N\xc3\x96TES.APP",
    ] {
        assert_eq!(
            reg.add(wrong, &g).map_err(Error::name),
            Err("FILE_NAME"),
            "{:?}",
            String::from_utf8_lossy(wrong)
        );
        assert_eq!(
            check_file_name(wrong, "notes").map_err(Error::name),
            Err("FILE_NAME")
        );
    }
    assert!(reg.is_empty(), "a refused entry changes nothing");
    let bad = entry("auth", "/SYSTEM/APPS/A.ELF", "تطبيق", "App", "-");
    assert_eq!(
        reg.add(b"AUTH.APP", &bad).map_err(Error::name),
        Err("RESERVED_ID")
    );
    assert!(reg.is_empty());
    assert_eq!(check_file_name(b"notes.app", "notes"), Ok(()));
    assert_eq!(check_file_name(b"NoTeS.ApP", "notes"), Ok(()));
    let app = reg.add(b"NOTES.APP", &g).expect("NOTES.APP");
    assert_eq!(app.id, "notes");
    assert_eq!(
        reg.find("notes").map(|a| a.elf),
        Some("/SYSTEM/APPS/NOTES.ELF")
    );
    assert_eq!(
        reg.add(b"notes.app", &g).map_err(Error::name),
        Err("DUP_ID")
    );
    assert_eq!(reg.len(), 1);
}

/// Every variant, checked by a match without a wildcard: a new variant does not compile here
/// until it has its place in ALL (and so in the contract check below).
const ALL: [Error; 17] = [
    Error::TooLarge,
    Error::Truncated,
    Error::BadUtf8,
    Error::ControlByte,
    Error::Syntax,
    Error::UnknownKey,
    Error::DupKey,
    Error::MissingKey,
    Error::BadId,
    Error::ReservedId,
    Error::BadElf,
    Error::BadName,
    Error::BadDeps,
    Error::DepNotAllowed,
    Error::FileName,
    Error::DupId,
    Error::TooMany,
];

fn position(e: Error) -> usize {
    match e {
        Error::TooLarge => 0,
        Error::Truncated => 1,
        Error::BadUtf8 => 2,
        Error::ControlByte => 3,
        Error::Syntax => 4,
        Error::UnknownKey => 5,
        Error::DupKey => 6,
        Error::MissingKey => 7,
        Error::BadId => 8,
        Error::ReservedId => 9,
        Error::BadElf => 10,
        Error::BadName => 11,
        Error::BadDeps => 12,
        Error::DepNotAllowed => 13,
        Error::FileName => 14,
        Error::DupId => 15,
        Error::TooMany => 16,
    }
}

fn contract() -> String {
    std::fs::read_to_string(root().join("docs/contracts/apps.md")).expect("apps.md")
}

/// The backticked words of the first contract line that starts with `prefix`, `skip` left out.
fn listed(text: &str, prefix: &str, skip: &str) -> Vec<String> {
    let line = text
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("apps.md has no line starting {prefix:?}"));
    let mut out: Vec<String> = line
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|w| *w != skip)
        .map(String::from)
        .collect();
    out.sort();
    out
}

fn sorted_strs(xs: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = xs.iter().map(|x| x.to_string()).collect();
    v.sort();
    v
}

#[test]
fn error_names_are_the_contracts() {
    for (i, e) in ALL.iter().enumerate() {
        assert_eq!(position(*e), i, "ALL lists {} out of place", e.name());
    }
    let text = contract();
    let s5 = text
        .split("## 5.")
        .nth(1)
        .and_then(|t| t.split("## 6.").next())
        .expect("apps.md §5");
    let mut table: Vec<String> = s5
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .map(String::from)
        .collect();
    table.sort();
    let names: Vec<&str> = ALL.iter().map(|e| e.name()).collect();
    assert_eq!(
        table,
        sorted_strs(&names),
        "apps.md §5's table and the Error enum differ"
    );
    assert_eq!(
        (FILE_MAX, MAX_APPS, ID_MAX, NAME_MAX_BYTES),
        (1024, 16, 8, 32)
    );
}

/// The reserved ids and the allowed dependencies are the contract's, exactly, in the crate and
/// in the model (both directions: nothing missing, nothing added).
#[test]
fn the_contracts_lists_equal_the_crates_and_the_models() {
    let text = contract();
    let reserved = listed(&text, "- المحجوزة (`RESERVED_ID`)", "RESERVED_ID");
    let allowed = listed(&text, "- القائمة البيضاء للتبعيات", "DEP_NOT_ALLOWED");
    assert_eq!(
        reserved,
        sorted_strs(&RESERVED),
        "apps.md §3 and nawah_apps::RESERVED differ"
    );
    assert_eq!(
        reserved,
        sorted_strs(&MODEL_RESERVED),
        "apps.md §3 and the model differ"
    );
    assert_eq!(
        allowed,
        sorted_strs(&ALLOWED_DEPS),
        "apps.md §3 and nawah_apps::ALLOWED_DEPS differ"
    );
    assert_eq!(
        allowed,
        sorted_strs(&MODEL_ALLOWED),
        "apps.md §3 and the model differ"
    );
    for id in &reserved {
        let file = entry(id, "/SYSTEM/APPS/X.ELF", "اسم", "Name", "-");
        assert_eq!(err(&file), "RESERVED_ID", "{id}");
    }
    for d in &allowed {
        let file = entry("x", "/SYSTEM/APPS/X.ELF", "اسم", "Name", d);
        assert!(parse(&file).is_ok_and(|a| a.deps.contains(d)), "{d}");
    }
}
