"""TST-M5-LAB-TOOL (host): the lab's monitor driver (tools/project.py run_qemu_monitored,
WP-27/WP-33) against a fake QEMU — a process that writes serial markers over time and serves
a monitor socket the way QEMU does: every step's commands must be sent once its marker has
appeared, in order, and a later step must not fire on an earlier marker; a single-step
`{after, commands}` case still works; `${SCREEN}` names the run's screendump and
`${SCREEN:tag}` (WP-37) one of several, `screen-<tag>.ppm` beside it, in commands and in
host-check arguments alike. `key-down`/`key-up` (WP-38) go through QMP on one connection kept
for the run: a key pressed in one step is released by a later step, within a bounded delay of
that step's marker. `cmd_boot` itself (WP-45) on the same fake QEMU: a case that ends by the
lab's `quit` fails when the guest ended first, in a single run and in a later phase; each
phase's console failures are kept, not overwritten by the next phase; a phase's own
`timeout_s` bounds that phase."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import project  # noqa: E402

FAKE_QEMU = r'''
import json, os, socket, sys, time, threading
serial, mon, record, script = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
qmp_path = sys.argv[5] if len(sys.argv) > 5 else None
got = []
qmp_got = []
marks = {}
t0 = time.monotonic()
def serve_qmp():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(qmp_path); s.listen(4)
    while True:
        c, _ = s.accept()
        c.sendall(b'{"QMP": {"version": {}, "capabilities": []}}\n')
        buf = b""
        while True:
            try:
                d = c.recv(4096)
            except OSError:
                break
            if not d:
                break
            buf += d
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                msg = json.loads(line)
                qmp_got.append([round(time.monotonic() - t0, 3), msg])
                c.sendall(b'{"event": "NOISE"}\n{"return": {}}\n')
                with open(record + ".qmp", "w") as f:
                    json.dump({"qmp": qmp_got, "marks": marks}, f)
        c.close()
if qmp_path:
    threading.Thread(target=serve_qmp, daemon=True).start()
def serve():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(mon); s.listen(4)
    while True:
        c, _ = s.accept()
        c.sendall(b"QEMU 0.0 monitor\n(qemu) ")
        buf = b""
        c.settimeout(3)
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
        except OSError:
            pass
        got.extend(l for l in buf.decode().split("\n") if l)
        with open(record, "w") as f:
            json.dump(got, f)
        c.close()
        if "quit" in got:
            os._exit(0)  # QEMU's monitor `quit` ends the emulator with status 0
threading.Thread(target=serve, daemon=True).start()
with open(serial, "ab") as f:
    for line, wait in script:
        time.sleep(wait)
        if line.startswith("__exit__"):
            os._exit(int(line[8:]))  # the guest ends by itself (a reset under -no-reboot is status 0)
        f.write((line + "\n").encode()); f.flush()
        marks[line] = round(time.monotonic() - t0, 3)
time.sleep(1.5)
if qmp_path:
    with open(record + ".qmp", "w") as f:
        json.dump({"qmp": qmp_got, "marks": marks}, f)
sys.exit(33)
'''


class MonitorSteps(unittest.TestCase):
    def drive(self, actions, script, timeout=20, sent=None):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            serial, mon, record = d / "serial.log", d / "mon.sock", d / "record.json"
            fake = d / "fake_qemu.py"
            fake.write_text(FAKE_QEMU)
            cmd = [sys.executable, "-I", str(fake), str(serial), str(mon), str(record), json.dumps(script),
                   str(project.qmp_socket_path(mon))]
            rc = project.run_qemu_monitored(cmd, d, d / "out.log", d / "err.log", timeout, serial, mon, actions, sent=sent)
            got = json.loads(record.read_text()) if record.exists() else []
            qmp_record = pathlib.Path(str(record) + ".qmp")
            self.qmp = json.loads(qmp_record.read_text()) if qmp_record.exists() else {"qmp": [], "marks": {}}
            return rc, got, (d / "out.log").read_text(), (d / "err.log").read_text()

    def test_single_step(self):
        rc, got, out, err = self.drive({"after": "|ready=1", "commands": ["sendkey a", "screendump ${SCREEN}",
                                                                          "screendump ${SCREEN:login}"]},
                                       [("boot", 0.1), ("OSX|x|ktest|t|ready=1", 0.3)])
        self.assertEqual(rc, 33)
        self.assertEqual(got[0], "sendkey a")
        self.assertTrue(got[1].startswith("screendump ") and got[1].endswith("/screen.ppm"), got)
        # A tagged screendump lands beside the run's own, under its tag.
        self.assertTrue(got[2].endswith("/screen-login.ppm"), got)
        self.assertEqual(pathlib.Path(got[1].split(" ", 1)[1]).parent, pathlib.Path(got[2].split(" ", 1)[1]).parent)
        self.assertIn("sent 3 command(s)", out)
        self.assertEqual(err.strip(), "")

    def test_steps_in_order(self):
        actions = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a", "sendkey shift-b"]},
                             {"after": "|phase=2|", "commands": ["sendkey a"]}]}
        # phase=2 appears only after phase=1; the second step must wait for it.
        rc, got, out, _ = self.drive(actions, [("OSX|x|ktest|t|phase=1|ready=1", 0.2),
                                               ("OSX|x|ktest|t|phase=2|ready=1", 1.0)])
        self.assertEqual(rc, 33)
        self.assertEqual(got, ["sendkey a", "sendkey shift-b", "sendkey a"])
        self.assertEqual(out.count("# monitor: sent"), 2)

    def test_later_step_needs_its_own_marker(self):
        actions = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a"]},
                             {"after": "|phase=2|", "commands": ["sendkey b"]}]}
        rc, got, out, _ = self.drive(actions, [("OSX|x|ktest|t|phase=1|ready=1", 0.2)])
        self.assertEqual(rc, 33)
        self.assertEqual(got, ["sendkey a"])
        self.assertEqual(out.count("# monitor: sent"), 1)

    def test_serial_substitution(self):
        text = "OSX|x|ktest|screen|rect=61,85,320,200|hash=0123456789abcdef|ready=1\nnext line\n"
        self.assertEqual(project.serial_value(text, "hash="), "0123456789abcdef")
        self.assertEqual(project.serial_value(text, "rect="), "61,85,320,200")
        self.assertEqual(project.serial_value(text, "absent="), "")
        arg = project.substitute_host_arg("${SERIAL:rect=},${SERIAL:hash=}", "/d", "bid", "/s.ppm", text)
        self.assertEqual(arg, "61,85,320,200,0123456789abcdef")
        self.assertEqual(project.substitute_host_arg("${SCREEN}", "/d", "bid", "/s.ppm", text), "/s.ppm")
        self.assertEqual(project.substitute_host_arg("${SCREEN:locked}", "/d", "bid", "/ev/1/screen.ppm", text),
                         "/ev/1/screen-locked.ppm")
        self.assertEqual(project.substitute_host_arg("a=${SCREEN:x-1},b=${SCREEN}", "/d", "b", "/e/screen.ppm", text),
                         "a=/e/screen-x-1.ppm,b=/e/screen.ppm")
        two = "OSX|x|dialog|window=21,45,260,242|a=1\nOSX|x|dialog|window=21,45,520,484|a=2\n"
        self.assertEqual(project.substitute_host_arg("${SERIAL_FIRST:window=} ${SERIAL:window=}", "/d", "b", "/s", two),
                         "21,45,260,242 21,45,520,484")
        self.assertEqual(project.substitute_host_arg("${EVIDENCE}/x", "/d", "b", "/s", two, "/ev/1"), "/ev/1/x")

    def test_key_held_across_steps_through_qmp(self):
        # WP-38 (M103): Enter goes down with the unlock and comes up only once the session's
        # answer is in the serial log, within RELEASE_WAIT of it, whatever auth's PBKDF2 took.
        # The answer was printed once before (the first login): `since_previous` waits for the
        # next one, after the press.
        actions = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a", "key-down ret"], "gap_s": 0.1},
                             {"after": "|answer|", "since_previous": True, "commands": ["key-up ret"]},
                             {"after": "|phase=3|", "commands": ["sendkey f"]}]}
        rc, got, out, err = self.drive(actions, [("OSX|x|session|answer|", 0.1),
                                                 ("OSX|x|ktest|t|phase=1|ready=1", 0.2),
                                                 ("OSX|x|session|answer|", 1.5),
                                                 ("OSX|x|ktest|t|phase=3|ready=1", 0.5)])
        self.assertEqual(rc, 33)
        self.assertEqual(err.strip(), "")
        self.assertEqual(got, ["sendkey a", "sendkey f"])
        msgs = [m for _, m in self.qmp["qmp"]]
        down = {"execute": "input-send-event", "arguments": {"events": [
            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "ret"}}}]}}
        up = {"execute": "input-send-event", "arguments": {"events": [
            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "ret"}}}]}}
        # One connection for the run: the handshake once, then the press and the release.
        self.assertEqual(msgs, [{"execute": "qmp_capabilities"}, down, up])
        t_down, t_up = self.qmp["qmp"][1][0], self.qmp["qmp"][2][0]
        t_answer = self.qmp["marks"]["OSX|x|session|answer|"]
        self.assertLess(t_down, t_answer, "the key goes down before the answer")
        self.assertGreaterEqual(t_up, t_answer, "the key comes up only after the answer")
        self.assertLess(t_up - t_answer, 0.5, "the release follows its marker well inside RELEASE_WAIT (1 s)")
        self.assertEqual(out.count("# monitor: sent"), 3)

    def test_since_previous_ignores_an_earlier_marker(self):
        actions = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a"]},
                             {"after": "|answer|", "since_previous": True, "commands": ["sendkey b"]}]}
        rc, got, out, _ = self.drive(actions, [("OSX|x|session|answer|", 0.1), ("OSX|x|ktest|t|phase=1|ready=1", 0.2)])
        self.assertEqual(rc, 33)
        self.assertEqual(got, ["sendkey a"], "an answer printed before the previous step must not fire the next")
        self.assertEqual(out.count("# monitor: sent"), 1)

    def test_qmp_without_server_is_reported(self):
        # No QMP socket: the step's failure is logged, the run goes on to its end.
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            serial, mon, record = d / "serial.log", d / "mon.sock", d / "record.json"
            fake = d / "fake_qemu.py"
            fake.write_text(FAKE_QEMU)
            cmd = [sys.executable, "-I", str(fake), str(serial), str(mon), str(record),
                   json.dumps([("OSX|x|ktest|t|phase=1|ready=1", 0.2)])]
            rc = project.run_qemu_monitored(cmd, d, d / "out.log", d / "err.log", 20, serial, mon,
                                            {"after": "|phase=1|", "commands": ["key-down ret"]})
            self.assertEqual(rc, 33)
            self.assertIn("monitor:", (d / "err.log").read_text())

    def test_qmp_link_recovers_after_a_failed_connect(self):
        # Review 2026-11-08: a failed connect or handshake left the socket set and unusable,
        # so every later key command of the run failed too. The link reconnects instead.
        import socket, threading
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "q.sock"
            link = project.QmpLink(path)
            with self.assertRaises(OSError):
                link.key("key-down ret")          # nothing listens yet
            self.assertIsNone(link.sock)
            got = []
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(path)); srv.listen(1)
            def serve():
                c, _ = srv.accept()
                c.sendall(b'{"QMP": {}}\n')
                buf = b""
                while len(got) < 2:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        got.append(json.loads(line)["execute"])
                        c.sendall(b'{"return": {}}\n')
                c.close()
            th = threading.Thread(target=serve, daemon=True); th.start()
            link.key("key-up ret")
            th.join(5); link.close(); srv.close()
            self.assertEqual(got, ["qmp_capabilities", "input-send-event"])

    def test_ends_by_monitor_quit(self):
        # WP-45 (PLAN-ANSWER §2.5 D2-Q2): an interactive case ends by the lab's `quit` (status 0,
        # also QEMU's status for a guest reset under -no-reboot): it passes only if every step
        # was sent and the last one ends with `quit`.
        actions = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a"]},
                             {"after": "|phase=2|", "commands": ["screendump ${SCREEN:end}", "quit"]}]}
        sent = []
        rc, got, out, _ = self.drive(actions, [("OSX|x|k|phase=1|", 0.2), ("OSX|x|k|phase=2|", 0.8), ("tail", 5.0)],
                                     sent=sent)
        self.assertEqual(rc, 0)
        self.assertEqual(sent, [0, 1])
        self.assertEqual(got[0], "sendkey a")
        self.assertEqual(got[-1], "quit")
        self.assertEqual(project.ends_by_failures("monitor", actions, sent), [])
        # A reset before the last step (status 0 too) is not an end by the lab.
        self.assertTrue(project.ends_by_failures("monitor", actions, [0]))
        # The last command must be `quit`; a case without steps cannot end by the monitor.
        self.assertTrue(project.ends_by_failures("monitor", {"after": "|x|", "commands": ["sendkey a"]}, [0]))
        self.assertTrue(project.ends_by_failures("monitor", None, []))
        self.assertTrue(project.ends_by_failures("reset", actions, [0, 1]))
        self.assertEqual(project.ends_by_failures(None, actions, []), [])

    def test_timeout_kills_qemu(self):
        rc, got, _, err = self.drive({"after": "|never|", "commands": ["sendkey a"]}, [("boot", 5.0)], timeout=2)
        self.assertEqual(rc, 124)
        self.assertEqual(got, [])
        self.assertIn("TIMEOUT", err)



class FakeConsole:
    """The COM2 session of a phase, reduced to its verdict: `fail` in the spec is what
    `finish()` reports."""

    def __init__(self, spec, transcript_path, serial_path, timeout):
        self.spec = spec

    def start(self):
        pass

    def finish(self):
        return list(self.spec.get("fail", []))


class CmdBoot(unittest.TestCase):
    """cmd_boot end to end on the fake QEMU: the target, the image preparation and the records
    are stubbed; the phase loop, the monitor driver, ends_by and the verdict are the real ones.
    A phase's fake-QEMU script travels in its qemu_extra."""

    QUIT = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a"], "gap_s": 0.1},
                      {"after": "|phase=2|", "commands": ["quit"], "gap_s": 0.1}]}
    GOOD = [("OSX|x|k|phase=1|", 0.2), ("OSX|x|k|phase=2|", 0.6), ("tail", 5.0)]
    RESET = [("OSX|x|k|phase=1|", 0.2), ("__exit__0", 1.0)]   # status 0 before the last step

    def boot(self, case):
        case = dict({"id": "T", "test_id": "T", "oracle": "o", "required_markers": [], "timeout_s": 20}, **case)
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td).resolve()
            out = root / "build" / "fake"
            out.mkdir(parents=True)
            (out / "build-id.txt").write_text("bid")
            (out / "K.EFI").write_bytes(b"k")
            fake = root / "fake_qemu.py"
            fake.write_text(FAKE_QEMU)
            run_dir = root / "run"
            run_dir.mkdir()
            t = {"build": {"artifact": "${OUT}/K.EFI", "inputs": []}, "qemu": {"boot_timeout_s": 20},
                 "boot_oracle": {"test_id": "B"}}
            verdicts = []

            def qemu_cmd(t_, name, esp, serial, extra=(), disk=None, smp=None, monitor=None, console_port=None):
                mon = monitor or (root / "unused.sock")
                return [sys.executable, "-I", str(fake), str(serial), str(mon), str(root / f"rec-{serial.stem}.json"),
                        extra[0], str(project.qmp_socket_path(mon))]

            env = {k: v for k, v in project.os.environ.items() if k != "NAWAH_QEMU_TIMEOUT_S"}
            with mock.patch.dict(project.os.environ, env, clear=True), \
                    mock.patch.multiple(project, ROOT=root, load_target=lambda n: t, begin_run=lambda: None,
                                        prepare_esp=lambda *a: root, prepare_disk=lambda *a, **k: root / "disk.img",
                                        qemu_cmd=qemu_cmd, new_run_dir=lambda slug: ("rid", run_dir),
                                        write_run=lambda *a, **k: None, digests_for=lambda *a: {},
                                        keep_artifact=lambda *a: "k", attach_evidence=lambda *a: None,
                                        ConsoleSession=FakeConsole,
                                        write_verdict=lambda d, rid, tid, v, *a, reason=None, **k: verdicts.append((v, reason))):
                project.cmd_boot("fake", suite_case=case)
            self.assertEqual(len(verdicts), 1)
            return verdicts[0]

    def script(self, lines):
        return [json.dumps(lines)]

    def test_ends_by_monitor_in_one_run(self):
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT}
        self.assertEqual(self.boot(dict(case, qemu_extra=self.script(self.GOOD)))[0], "PASS")
        verdict, reason = self.boot(dict(case, qemu_extra=self.script(self.RESET)))
        self.assertEqual(verdict, "FAIL")
        self.assertIn("the run ended before the lab", reason)

    def test_ends_by_monitor_in_a_later_phase(self):
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT}
        good = {"qemu_extra": self.script(self.GOOD)}
        self.assertEqual(self.boot(dict(case, phases=[good, dict(good)]))[0], "PASS")
        verdict, reason = self.boot(dict(case, phases=[good, {"qemu_extra": self.script(self.RESET)}]))
        self.assertEqual(verdict, "FAIL")
        self.assertIn("phase 2", reason)
        self.assertIn("the run ended before the lab", reason)

    def test_console_failures_of_every_phase_are_kept(self):
        good = {"qemu_extra": self.script(self.GOOD)}
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT,
                "phases": [dict(good, console={"port": 1, "fail": ["console: svc listed 7 services"]}),
                           dict(good, console={"port": 2})]}
        verdict, reason = self.boot(case)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("phase 1: console: svc listed 7 services", reason)

    def test_a_phase_timeout_bounds_that_phase(self):
        import time
        slow = self.script([("boot", 8.0)])           # exits 33 after ~9.5 s
        case = {"expected_exit_code": 33, "phases": [{"qemu_extra": slow, "timeout_s": 2}]}
        begin = time.monotonic()
        verdict, reason = self.boot(case)
        self.assertEqual((verdict, reason), ("FAIL", "timeout (hang)"))
        self.assertLess(time.monotonic() - begin, 7)


if __name__ == "__main__":
    unittest.main()
