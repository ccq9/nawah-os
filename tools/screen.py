#!/usr/bin/env python3
"""tools/screen.py — the lab's eye on the guest's frame (WP-32, display.md part A): reads a
QEMU `screendump` (binary PPM, P6) and checks it against what the kernel declared it drew.
Independent of the kernel's own read-back: the picture comes from the emulator's VGA memory.

  screen.py probe IMG --build-id ID [--corner N] [--cell N] [--square X,Y,RGB ...]

Checks: the frame's size is printed; the four 32×32 corners carry red, green, blue and white;
the build-id bar (one 16×16 cell per hex digit at x = 2·corner on the top edge) decodes to
`--build-id`; every `--square X,Y,RRGGBB` (64×64) has that colour at its centre. Exit 0 when
all hold, 1 otherwise, with a JSON summary on stdout.
"""
import argparse, json, sys

DIGIT_COLOURS = [0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0,
                 0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF]
CORNER_COLOURS = [0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF]


def read_ppm(path):
    data = open(path, "rb").read()
    # P6 header: magic, width, height, maxval, each separated by whitespace, comments allowed.
    tokens, i = [], 0
    while len(tokens) < 4:
        while data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":
            while data[i:i + 1] not in (b"\n", b""):
                i += 1
            continue
        start = i
        while not data[i:i + 1].isspace():
            i += 1
        tokens.append(data[start:i])
    i += 1  # the single whitespace after maxval
    if tokens[0] != b"P6" or tokens[3] != b"255":
        raise SystemExit(f"not a binary PPM with 8-bit samples: {tokens}")
    w, h = int(tokens[1]), int(tokens[2])
    px = data[i:i + w * h * 3]
    if len(px) != w * h * 3:
        raise SystemExit(f"short pixel data: {len(px)} != {w * h * 3}")
    return w, h, px


def rgb_at(img, x, y):
    w, h, px = img
    if not (0 <= x < w and 0 <= y < h):
        return None
    o = (y * w + x) * 3
    return (px[o] << 16) | (px[o + 1] << 8) | px[o + 2]


def near(a, b, tol=8):
    return a is not None and all(abs(((a >> s) & 0xFF) - ((b >> s) & 0xFF)) <= tol for s in (16, 8, 0))


def nearest_digit(c):
    best, dist = None, None
    for k, d in enumerate(DIGIT_COLOURS):
        e = sum(abs(((c >> s) & 0xFF) - ((d >> s) & 0xFF)) for s in (16, 8, 0))
        if dist is None or e < dist:
            best, dist = k, e
    return best if dist is not None and dist <= 24 else None


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("image")
    p.add_argument("--build-id", required=True)
    p.add_argument("--corner", type=int, default=32)
    p.add_argument("--cell", type=int, default=16)
    p.add_argument("--square", action="append", default=[], help="X,Y,RRGGBB of a 64x64 square")
    a = ap.parse_args()
    img = read_ppm(a.image)
    w, h, _ = img
    c = a.corner
    corners = [rgb_at(img, c // 2, c // 2), rgb_at(img, w - c // 2, c // 2), rgb_at(img, c // 2, h - c // 2), rgb_at(img, w - c // 2, h - c // 2)]
    corners_ok = all(near(v, e) for v, e in zip(corners, CORNER_COLOURS))
    decoded = ""
    for i in range(len(a.build_id)):
        v = rgb_at(img, 2 * c + i * a.cell + a.cell // 2, a.cell // 2)
        k = nearest_digit(v) if v is not None else None
        decoded += "%x" % k if k is not None else "?"
    bar_ok = decoded == a.build_id.lower()
    squares = []
    for spec in a.square:
        x, y, colour = spec.split(",")
        x, y, colour = int(x), int(y), int(colour, 16)
        v = rgb_at(img, x + 32, y + 32)
        squares.append({"x": x, "y": y, "expected": "%06x" % colour, "seen": None if v is None else "%06x" % v, "ok": near(v, colour)})
    ok = corners_ok and bar_ok and all(s["ok"] for s in squares)
    print(json.dumps({"width": w, "height": h, "corners": ["%06x" % v if v is not None else None for v in corners], "corners_ok": corners_ok,
                      "bar": decoded, "bar_ok": bar_ok, "squares": squares, "ok": ok}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
