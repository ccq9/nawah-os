#!/usr/bin/env python3
"""tools/text_check.py — the lab's host-side check of TST-M5-TEXT-GUEST (WP-35): renders the
line textprobe draws (its constants are read from user/apps/textprobe/src/main.rs, the one
source) with the host build of nawah-text, and compares the box's FNV-1a hash with the one the
guest traced. Usage: text_check.py --rect X,Y,W,H --hash HEX"""
import argparse, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROBE = ROOT / "user" / "apps" / "textprobe" / "src" / "main.rs"
FONTS = ROOT / "platform" / "assets" / "fonts"
TEXTDUMP = ROOT / "target" / "x86_64-unknown-linux-gnu" / "release" / "examples" / "textdump"


def constants():
    src = PROBE.read_text(encoding="utf-8")
    c = {k: re.search(rf"const {k}: \w+ = (0x[0-9A-Fa-f]+|\d+);", src).group(1) for k in
         ("LINE_W", "LINE_H", "LINE_X", "LINE_Y", "LINE_PX", "LINE_FG", "LINE_BG")}
    c = {k: int(v, 0) for k, v in c.items()}
    body = re.search(r"const LINE: &\[u32\] = &\[(.*?)\];", src, re.S).group(1)
    c["LINE"] = [int(x, 0) for x in re.findall(r"0x[0-9A-Fa-f]+", body)]
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rect", required=True)
    ap.add_argument("--hash", required=True)
    a = ap.parse_args()
    c = constants()
    want_rect = f"{c['LINE_X']},{c['LINE_Y']},{c['LINE_W']},{c['LINE_H']}"
    subprocess.run(["cargo", "build", "--offline", "--release", "-p", "nawah-text", "--target", "x86_64-unknown-linux-gnu",
                    "--examples"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    cmd = "render auto %d %d %d %06x %06x %s\n" % (c["LINE_PX"], c["LINE_W"], c["LINE_H"], c["LINE_FG"], c["LINE_BG"],
                                                    " ".join("%x" % cp for cp in c["LINE"]))
    r = subprocess.run([str(TEXTDUMP), str(FONTS / "NotoSans-Regular.ttf"), str(FONTS / "NotoSansArabic-Regular.ttf")],
                       input=cmd, capture_output=True, text=True, check=True)
    host = r.stdout.split()[0]
    ok = a.rect == want_rect and host == a.hash.lower()
    print(f"guest rect={a.rect} hash={a.hash}; host rect={want_rect} hash={host} ({r.stdout.split()[1]}): "
          + ("equal" if ok else "DIFFERENT"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
