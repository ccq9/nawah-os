//! Runs BidiCharacterTest.txt (the Unicode conformance data) through `nawah_text::bidi`:
//! `bidi_check <file>` prints `lines=<n> pass=<n> fail=<n>` and the first failures; exit 1
//! when any line fails.

use nawah_text::bidi::{reorder, Base, Bidi, REMOVED};
use std::io::{BufRead, BufReader};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("path to BidiCharacterTest.txt");
    let file = std::fs::File::open(&path).expect("open");
    let mut bidi = Box::new(Bidi::new());
    let (mut lines, mut pass, mut fail) = (0u64, 0u64, 0u64);
    let mut shown = 0;
    for line in BufReader::new(file).lines() {
        let line = line.expect("read");
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(';').collect();
        if fields.len() < 5 {
            continue;
        }
        lines += 1;
        let text: Vec<u32> = fields[0]
            .split_whitespace()
            .map(|h| u32::from_str_radix(h, 16).expect("hex"))
            .collect();
        let base = match fields[1] {
            "0" => Base::Ltr,
            "1" => Base::Rtl,
            _ => Base::Auto,
        };
        let want_para: u8 = fields[2].parse().expect("para level");
        let want_levels: Vec<Option<u8>> = fields[3]
            .split_whitespace()
            .map(|t| {
                if t == "x" {
                    None
                } else {
                    Some(t.parse().expect("level"))
                }
            })
            .collect();
        let want_order: Vec<u16> = fields[4]
            .split_whitespace()
            .map(|t| t.parse().expect("index"))
            .collect();
        let mut levels = vec![0u8; text.len()];
        let para = bidi.resolve(&text, base, &mut levels);
        let got_levels: Vec<Option<u8>> = levels
            .iter()
            .map(|&l| if l == REMOVED { None } else { Some(l) })
            .collect();
        let mut order = vec![0u16; text.len()];
        let n = reorder(&levels, &mut order);
        order.truncate(n);
        if para == want_para && got_levels == want_levels && order == want_order {
            pass += 1;
        } else {
            fail += 1;
            if shown < 10 {
                shown += 1;
                println!(
                    "FAIL {}\n  para {} (want {})\n  levels {:?}\n  want   {:?}\n  order {:?}\n  want  {:?}",
                    line, para, want_para, got_levels, want_levels, order, want_order
                );
            }
        }
    }
    println!("lines={} pass={} fail={}", lines, pass, fail);
    if fail > 0 {
        std::process::exit(1);
    }
}
