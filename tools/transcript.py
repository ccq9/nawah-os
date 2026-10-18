#!/usr/bin/env python3
"""tools/transcript.py — the lab's check of the narrator's transcript (WP-36, ui.md §3): the
lines the narrator wrote (`…|user|trace|…|text=narrator|<text>` in the serial log) must equal
the expected file, line for line and in order — nothing missing, nothing extra — in every
serial log of the run (each phase of a multi-phase case: the same transcript in every run).

  transcript.py check EVIDENCE_DIR EXPECTED_FILE
  transcript.py dims BEFORE AFTER FACTOR      (x,y,w,h pairs: same origin, size × FACTOR)
"""
import pathlib, sys

MARK = "|text=narrator|"


def narrator_lines(text):
    return [line.split(MARK, 1)[1].rstrip("\r") for line in text.splitlines() if MARK in line]


def check(evidence, expected_file):
    expected = [l for l in pathlib.Path(expected_file).read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    # A multi-phase case keeps one log per boot (serial-N.log) besides their concatenation
    # (serial.log): each boot is checked on its own.
    logs = sorted(pathlib.Path(evidence).glob("serial-*.log")) or sorted(pathlib.Path(evidence).glob("serial.log"))
    if not logs:
        print("no serial log"); return 1
    ok = True
    for log in logs:
        got = narrator_lines(log.read_text(errors="replace"))
        if got == expected:
            print(f"{log.name}: {len(got)} narrator lines as expected")
            continue
        ok = False
        print(f"{log.name}: transcript differs ({len(got)} lines, {len(expected)} expected)")
        for i in range(max(len(got), len(expected))):
            a = got[i] if i < len(got) else "<missing>"
            b = expected[i] if i < len(expected) else "<extra>"
            if a != b:
                print(f"  line {i + 1}: got      {a}\n          expected {b}")
    return 0 if ok else 1


def dims(before, after, factor):
    b = [int(v) for v in before.split(",")]
    a = [int(v) for v in after.split(",")]
    f = int(factor)
    ok = len(a) == len(b) == 4 and a[:2] == b[:2] and a[2] == f * b[2] and a[3] == f * b[3]
    print(f"before {b} after {a}: " + ("same origin, size x%d" % f if ok else "NOT scaled as expected"))
    return 0 if ok else 1


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        return check(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 5 and sys.argv[1] == "dims":
        return dims(sys.argv[2], sys.argv[3], sys.argv[4])
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
