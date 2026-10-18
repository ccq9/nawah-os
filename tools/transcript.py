#!/usr/bin/env python3
"""tools/transcript.py — the lab's check of the narrator's transcript (WP-36, ui.md §3): the
lines the narrator wrote (`…|user|trace|…|text=narrator|<text>` in the serial log) must equal
the expected file, line for line and in order — nothing missing, nothing extra — in every
serial log of the run (each phase of a multi-phase case: the same transcript in every run).

`streams` (WP-37, session.md §9) checks several programs at once: every line of the expected
file starts with a stream name (`session|…`, `spy|…`, `narrator|…`), and for each stream the
file names, the trace texts of that stream must equal the file's lines of that stream exactly
and in order. How the streams interleave is not checked (separate processes race); streams
the file does not name are ignored.

  transcript.py check EVIDENCE_DIR EXPECTED_FILE
  transcript.py streams EVIDENCE_DIR EXPECTED_FILE
  transcript.py dims BEFORE AFTER FACTOR      (x,y,w,h pairs: same origin, size × FACTOR)
"""
import pathlib, sys

MARK = "|text=narrator|"


def narrator_lines(text):
    return [line.split(MARK, 1)[1].rstrip("\r") for line in text.splitlines() if MARK in line]


def expected_lines(expected_file):
    return [l for l in pathlib.Path(expected_file).read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]


def serial_logs(evidence):
    # A multi-phase case keeps one log per boot (serial-N.log) besides their concatenation
    # (serial.log): each boot is checked on its own.
    return sorted(pathlib.Path(evidence).glob("serial-*.log")) or sorted(pathlib.Path(evidence).glob("serial.log"))


def diff(got, expected):
    for i in range(max(len(got), len(expected))):
        a = got[i] if i < len(got) else "<missing>"
        b = expected[i] if i < len(expected) else "<extra>"
        if a != b:
            print(f"  line {i + 1}: got      {a}\n          expected {b}")


def trace_texts(text):
    """Every user trace's text (`…|text=<text>`), in order."""
    out = []
    for line in text.splitlines():
        i = line.find("|text=")
        if i >= 0 and "|user|trace|" in line[:i + 1]:
            out.append(line[i + 6:].rstrip("\r"))
    return out


def streams(evidence, expected_file):
    expected = expected_lines(expected_file)
    names = list(dict.fromkeys(l.split("|", 1)[0] for l in expected))
    logs = serial_logs(evidence)
    if not logs:
        print("no serial log"); return 1
    ok = True
    for log in logs:
        texts = trace_texts(log.read_text(errors="replace"))
        for name in names:
            got = [t for t in texts if t.split("|", 1)[0] == name]
            want = [l for l in expected if l.split("|", 1)[0] == name]
            if got == want:
                print(f"{log.name}: {name}: {len(got)} lines as expected")
                continue
            ok = False
            print(f"{log.name}: {name}: stream differs ({len(got)} lines, {len(want)} expected)")
            diff(got, want)
    return 0 if ok else 1


def check(evidence, expected_file):
    expected = expected_lines(expected_file)
    logs = serial_logs(evidence)
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
        diff(got, expected)
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
    if len(sys.argv) == 4 and sys.argv[1] == "streams":
        return streams(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 5 and sys.argv[1] == "dims":
        return dims(sys.argv[2], sys.argv[3], sys.argv[4])
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
