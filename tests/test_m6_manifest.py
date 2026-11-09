"""TST-M6-MANIFEST-LINT (host, REQ-M6-002, WP-45): the system manifest
platform/pc-qemu/manifests/services.txt (/SYSTEM/SERVICES.TXT, services.md §2 v1.11) and the lab
self-test manifest selftest.txt (/SYSTEM/SELFTEST.TXT) checked on the host before any guest
boots them (docs/PLAN-ANSWER.md §2.2 D1/D2): ASCII text and the grammar of services.md §2; by
the table of services.md §0.000, the eight services in that order, each with exactly the
table's dependencies (every one declared on an earlier line), all on-failure, the minimum
readiness timeouts of auth and session, watchdog= on input and display and nowhere a service
does not answer PONG; 8.3 image names the build makes, under the manager's MANIFEST_MAX; the
self-test manifest is ASCII, starts nothing and names mode=selftest. The lint is checked
against itself on manifests with one defect each, one per rule (no lint branch is dead)."""

import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFESTS = ROOT / "platform" / "pc-qemu" / "manifests"
MANIFEST_MAX = 4096          # user/apps/svcmgr/src/main.rs: the manager reads at most this much
MAX_SERVICES = 16            # services.md §2
SYSTEM = ("auth", "config", "net", "input", "display", "narrator", "session", "sh")
DEPS = {"auth": set(), "config": set(), "net": set(), "input": set(), "display": {"input"},   # services.md §0.000
        "narrator": {"display"}, "session": {"auth", "input", "display", "config", "narrator"}, "sh": {"auth", "net"}}
WATCHDOG = {"input", "display"}                                     # services.md §0.000: they answer PONG
MIN_TIMEOUT = {"auth": 60000, "session": 30000}                    # PLAN-ANSWER §2.2 D2
NAME = re.compile(r"[A-Za-z0-9_-]{1,15}")
IMAGE = re.compile(r"/SYSTEM/([A-Z0-9_]{1,8})\.ELF")


def built_apps():
    """Stems of the applications the build puts on the volume (≤ 8 characters: prepare_disk)."""
    t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
    stems = [pathlib.PurePosixPath(a).stem for a in t["build"]["extra_artifacts"] if a.startswith("${OUT}/apps/")]
    return {s for s in stems if len(s) <= 8}


def answers_pong(stem):
    src = ROOT / "user" / "apps" / stem / "src" / "main.rs"
    return src.exists() and 'b"PONG"' in src.read_text(encoding="utf-8")


def parse(text):
    """(services, errors) by services.md §2."""
    services, errors = [], []
    if len(text.encode()) >= MANIFEST_MAX:
        errors.append(f"{len(text.encode())} bytes, the manager reads < {MANIFEST_MAX}")
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split()
        if len(f) < 7:
            errors.append(f"line {n}: {len(f)} fields, 7 needed"); continue
        name, path, deps, timeout, restart, max_restarts, backoff = f[:7]
        rest = f[7:]
        watchdog = 0
        if rest and rest[0].startswith("watchdog="):
            if not rest[0][9:].isdigit():
                errors.append(f"line {n}: {rest[0]}")
            else:
                watchdog = int(rest[0][9:])
            rest = rest[1:]
        if len(" ".join(rest).encode()) > 64:
            errors.append(f"line {n}: arg longer than 64 bytes")
        if not NAME.fullmatch(name):
            errors.append(f"line {n}: name {name!r}")
        if restart not in ("never", "on-failure"):
            errors.append(f"line {n}: restart {restart!r}")
        for v in (timeout, max_restarts, backoff):
            if not v.isdigit():
                errors.append(f"line {n}: {v!r} is not a decimal number")
        services.append({"line": n, "name": name, "path": path, "deps": [] if deps == "-" else deps.split(","),
                         "timeout": int(timeout) if timeout.isdigit() else -1, "restart": restart, "watchdog": watchdog})
    return services, errors


def lint(text, apps, pong=answers_pong):
    """Rules every manifest the lab ships must keep."""
    services, errors = parse(text)
    if len(services) > MAX_SERVICES:
        errors.append(f"{len(services)} services (TOO_MANY > {MAX_SERVICES})")
    seen = set()
    for s in services:
        if s["name"] in seen:
            errors.append(f"line {s['line']}: duplicate service {s['name']}")
        for d in s["deps"]:
            if d not in seen:
                errors.append(f"line {s['line']}: {s['name']} depends on {d!r}, not declared on an earlier line")
        seen.add(s["name"])
        m = IMAGE.fullmatch(s["path"])
        if not m:
            errors.append(f"line {s['line']}: image {s['path']!r} is not /SYSTEM/<8.3>.ELF")
        elif m.group(1).lower() not in apps:
            errors.append(f"line {s['line']}: image {s['path']} is not an application the build makes")
        elif s["watchdog"] and not pong(m.group(1).lower()):
            errors.append(f"line {s['line']}: watchdog= on {s['name']}, whose source never answers PONG")
    return services, errors


def lint_system(text, apps, pong=answers_pong):
    """The system manifest of the interactive boot (services.md v1.11)."""
    services, errors = lint(text, apps, pong)
    names = tuple(s["name"] for s in services)
    if names != SYSTEM:
        errors.append(f"services {names}, expected {SYSTEM} in that order")
    for s in services:
        if s["restart"] != "on-failure":
            errors.append(f"{s['name']}: restart {s['restart']}, expected on-failure")
        if s["timeout"] < MIN_TIMEOUT.get(s["name"], 1):
            errors.append(f"{s['name']}: timeout {s['timeout']} below {MIN_TIMEOUT.get(s['name'], 1)}")
        if s["name"] in DEPS and set(s["deps"]) != DEPS[s["name"]]:
            errors.append(f"{s['name']} depends on {sorted(s['deps'])}, services.md §0.000 gives {sorted(DEPS[s['name']])}")
        if s["name"] in WATCHDOG and not s["watchdog"]:
            errors.append(f"{s['name']}: no watchdog= (services.md §0.000)")
    return errors


def lint_selftest(text, apps, pong=answers_pong):
    """The lab self-test manifest (services.md v1.11): comments only, naming its boot mode."""
    services, errors = lint(text, apps, pong)
    if services:
        errors.append(f"the self-test manifest starts {len(services)} service(s); TST-M1-BOOT expects OK 0")
    if "mode=selftest" not in text:
        errors.append("the self-test manifest does not name the boot mode that loads it (mode=selftest)")
    return errors


GOOD = """# a sample with the shape of the system manifest
auth     /SYSTEM/AUTHD.ELF     -                                  60000 on-failure 3 100
config   /SYSTEM/CONFIGD.ELF   -                                   5000 on-failure 3 100
net      /SYSTEM/NETD.ELF      -                                   5000 on-failure 3 100
input    /SYSTEM/INPUTD.ELF    -                                   5000 on-failure 3 10 watchdog=2000
display  /SYSTEM/DISPLAYD.ELF  input                               5000 on-failure 3 10 watchdog=2000
narrator /SYSTEM/NARRATOR.ELF  display                             5000 on-failure 3 100
session  /SYSTEM/SESSIOND.ELF  auth,input,display,config,narrator 30000 on-failure 5 100
sh       /SYSTEM/SH.ELF        auth,net                            5000 on-failure 3 100
"""
APPS = {"authd", "configd", "netd", "inputd", "displayd", "narrator", "sessiond", "sh"}
PONG = {"inputd", "displayd"}.__contains__


def check_ascii(name, raw):
    """services.md §2: the manifest is ASCII text; a non-ASCII byte is named, not decoded away."""
    bad = [i for i, b in enumerate(raw) if b > 0x7F]
    return raw.decode("ascii", errors="replace"), [f"{name}: non-ASCII byte at offset {i}" for i in bad[:3]]


def lines(text):
    return text.splitlines(keepends=True)


class SystemManifest(unittest.TestCase):
    def test_system_manifest(self):
        text, errors = check_ascii("services.txt", (MANIFESTS / "services.txt").read_bytes())
        self.assertEqual(errors + lint_system(text, built_apps()), [])

    def test_selftest_manifest(self):
        text, errors = check_ascii("selftest.txt", (MANIFESTS / "selftest.txt").read_bytes())
        self.assertEqual(errors + lint_selftest(text, built_apps()), [])


class LintRejects(unittest.TestCase):
    def setUp(self):
        self.assertEqual(lint_system(GOOD, APPS, PONG), [])

    def test_a_missing_service(self):
        bad = "".join(l for l in lines(GOOD) if not l.startswith("narrator"))
        errors = lint_system(bad, APPS, PONG)
        self.assertTrue(any("expected" in e for e in errors), errors)
        self.assertTrue(any("depends on 'narrator'" in e for e in errors), errors)

    def test_two_services_swapped(self):
        ls = lines(GOOD)
        ls[1], ls[2] = ls[2], ls[1]          # auth and config: no dependency between them
        self.assertTrue(any("in that order" in e for e in lint_system("".join(ls), APPS, PONG)))
        ls = lines(GOOD)
        ls[4], ls[5] = ls[5], ls[4]          # input after display, which depends on it
        self.assertTrue(any("not declared on an earlier line" in e for e in lint_system("".join(ls), APPS, PONG)))

    def test_a_duplicate_service(self):
        bad = GOOD + "net      /SYSTEM/NETD.ELF      -                                   5000 on-failure 3 100\n"
        self.assertTrue(any("duplicate service net" in e for e in lint_system(bad, APPS, PONG)))

    def test_a_watchdog_without_pong(self):
        bad = GOOD.replace("/SYSTEM/NARRATOR.ELF  display                             5000 on-failure 3 100",
                           "/SYSTEM/NARRATOR.ELF  display                             5000 on-failure 3 100 watchdog=2000")
        self.assertNotEqual(bad, GOOD)
        self.assertTrue(any("never answers PONG" in e for e in lint_system(bad, APPS, PONG)))

    def test_an_image_that_is_not_8_3_or_not_built(self):
        bad = GOOD.replace("/SYSTEM/SESSIOND.ELF", "/SYSTEM/SESSIONSVC.ELF")
        self.assertTrue(any("is not /SYSTEM/<8.3>.ELF" in e for e in lint_system(bad, APPS, PONG)))
        bad = GOOD.replace("/SYSTEM/SH.ELF", "/SYSTEM/SHELL.ELF")
        self.assertTrue(any("not an application the build makes" in e for e in lint_system(bad, APPS, PONG)))


def swap(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


class EveryRuleRejects(unittest.TestCase):
    """One manifest per rule the oracle claims, each with that one defect: no lint branch is
    dead (audit G8)."""

    def system(self, text):
        return lint_system(text, APPS, PONG)

    def assertRejects(self, errors, needle):
        self.assertTrue(any(needle in e for e in errors), f"{needle!r} not in {errors}")

    def test_a_non_ascii_byte(self):
        text, errors = check_ascii("x.txt", GOOD.replace("# a sample", "# a sample \u2014").encode("utf-8"))
        self.assertRejects(errors, "x.txt: non-ASCII byte at offset")
        self.assertEqual(check_ascii("x.txt", GOOD.encode())[1], [])

    def test_the_size_limit(self):
        pad = "#" + "x" * 98 + "\n"
        big = GOOD + pad * ((MANIFEST_MAX - len(GOOD)) // len(pad) + 1)
        self.assertRejects(self.system(big), f"the manager reads < {MANIFEST_MAX}")
        fits = GOOD + pad * ((MANIFEST_MAX - 1 - len(GOOD)) // len(pad))
        self.assertEqual(self.system(fits), [])

    def test_never_instead_of_on_failure(self):
        bad = swap(GOOD, "5000 on-failure 3 100\nnet", "5000 never 3 100\nnet")
        self.assertRejects(self.system(bad), "config: restart never, expected on-failure")

    def test_a_timeout_too_short(self):
        self.assertRejects(self.system(swap(GOOD, "narrator 30000", "narrator 29999")), "session: timeout 29999 below 30000")
        self.assertRejects(self.system(swap(GOOD, "-                                  60000", "-                                  59999")),
                           "auth: timeout 59999 below 60000")

    def test_session_without_config(self):
        bad = swap(GOOD, "auth,input,display,config,narrator", "auth,input,display,narrator")
        self.assertRejects(self.system(bad), "session depends on")

    def test_every_service_has_its_table_dependencies(self):
        bad = swap(GOOD, "/SYSTEM/NARRATOR.ELF  display ", "/SYSTEM/NARRATOR.ELF  -       ")
        self.assertRejects(self.system(bad), "narrator depends on")
        bad = swap(GOOD, "/SYSTEM/SH.ELF        auth,net ", "/SYSTEM/SH.ELF        auth,net,config ")
        self.assertRejects(self.system(bad), "sh depends on")

    def test_a_watchdog_missing_where_the_table_gives_one(self):
        bad = swap(GOOD, "/SYSTEM/INPUTD.ELF    -                                   5000 on-failure 3 10 watchdog=2000",
                   "/SYSTEM/INPUTD.ELF    -                                   5000 on-failure 3 10")
        self.assertRejects(self.system(bad), "input: no watchdog=")
        bad = swap(GOOD, "input                               5000 on-failure 3 10 watchdog=2000",
                   "input                               5000 on-failure 3 10")
        self.assertRejects(self.system(bad), "display: no watchdog=")

    def test_a_selftest_manifest_with_a_service(self):
        good = "# mode=selftest: no service\n"
        self.assertEqual(lint_selftest(good, APPS, PONG), [])
        bad = good + "net      /SYSTEM/NETD.ELF      -   5000 on-failure 3 100\n"
        self.assertRejects(lint_selftest(bad, APPS, PONG), "the self-test manifest starts 1 service")

    def test_a_selftest_manifest_without_its_mode(self):
        self.assertRejects(lint_selftest("# no service\n", APPS, PONG), "mode=selftest")

    def test_the_grammar(self):
        cases = {
            "6 fields, 7 needed": swap(GOOD, "5000 on-failure 3 100\nnet", "5000 on-failure 3\nnet"),
            "watchdog=x": swap(GOOD, "3 10 watchdog=2000\ndisplay", "3 10 watchdog=x\ndisplay"),
            "arg longer than 64 bytes": swap(GOOD, "auth,net                            5000 on-failure 3 100",
                                             "auth,net                            5000 on-failure 3 100 " + "a" * 65),
            "name 'ne.t'": swap(GOOD, "\nnet ", "\nne.t "),
            "restart 'always'": swap(GOOD, "5000 on-failure 3 100\nnet", "5000 always 3 100\nnet"),
            "'1x' is not a decimal number": swap(GOOD, "5000 on-failure 3 100\nnet", "5000 on-failure 1x 100\nnet"),
            "TOO_MANY": GOOD + "".join(f"x{i} /SYSTEM/NETD.ELF - 5000 on-failure 3 100\n" for i in range(9)),
        }
        for needle, bad in cases.items():
            with self.subTest(needle):
                self.assertRejects(self.system(bad), needle)


if __name__ == "__main__":
    unittest.main()
