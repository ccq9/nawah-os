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
`timeout_s` bounds that phase. A forbidden marker of the case or of a phase fails it when it
appears in the guest's received console transcript (console.log) as in the serial log, and
the received transcript of the real ConsoleSession holds the guest's bytes, never the lab's
own `>>> ` lines (WP-82)."""

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
        if line.startswith("__signal_once__") and not os.path.exists(record + ".died"):
            open(record + ".died", "w").close()
            os.kill(os.getpid(), int(line[15:]))  # the emulator itself dies (QEMU's SIGSEGV), once
        if line.startswith("__signal_once__"):
            continue
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
    `finish()` reports and `received` what the guest sent on the console (WP-82), which
    `finish()` writes to its transcript path as the real session does."""

    def __init__(self, spec, transcript_path, serial_path, timeout):
        self.spec, self.transcript_path = spec, transcript_path
        # `attempts` (a list) gives each new session of the phase its own (received, fail).
        self.attempt = spec["attempts"].pop(0) if spec.get("attempts") else (spec.get("received", ""), spec.get("fail", []))
        self.received = self.attempt[0].encode()

    def start(self):
        pass

    def finish(self):
        self.transcript_path.write_bytes(self.received)
        return list(self.attempt[1])


class CmdBoot(unittest.TestCase):
    """cmd_boot end to end on the fake QEMU: the target, the image preparation and the records
    are stubbed; the phase loop, the monitor driver, ends_by and the verdict are the real ones.
    A phase's fake-QEMU script travels in its qemu_extra."""

    QUIT = {"steps": [{"after": "|phase=1|", "commands": ["sendkey a"], "gap_s": 0.1},
                      {"after": "|phase=2|", "commands": ["quit"], "gap_s": 0.1}]}
    GOOD = [("OSX|x|k|phase=1|", 0.2), ("OSX|x|k|phase=2|", 0.6), ("tail", 5.0)]
    RESET = [("OSX|x|k|phase=1|", 0.2), ("__exit__0", 1.0)]   # status 0 before the last step

    def boot(self, case, files=None):
        """The verdict of `case`; `files`, when given, receives the run directory's files
        ({name: bytes}) before the directory goes."""
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
            if files is not None:
                files.update({f.name: f.read_bytes() for f in run_dir.iterdir() if f.is_file()})
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

    def test_forbidden_marker_in_the_received_console_transcript_fails(self):
        # WP-82: the case's forbidden markers are checked on what the guest sent on the
        # console (console.log) as on the serial log; absent there, the case passes.
        good = {"qemu_extra": self.script(self.GOOD)}
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT,
                "forbidden_markers": ["lab-user-1"]}
        clean = dict(case, phases=[dict(good, console={"port": 1, "received": "nawah> svc\nauth ready\n"})])
        self.assertEqual(self.boot(clean)[0], "PASS")
        leak = dict(case, phases=[dict(good, console={"port": 1, "received": "nawah> svc\nlab-user-1\n"})])
        verdict, reason = self.boot(leak)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("lab-user-1", reason)
        self.assertIn("console.log", reason)

    def test_a_phase_forbidden_marker_in_its_received_console_transcript_fails(self):
        good = {"qemu_extra": self.script(self.GOOD)}
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT}
        ph = dict(good, forbidden_markers=["secret"], console={"port": 1, "received": "x secret y"})
        verdict, reason = self.boot(dict(case, phases=[ph, dict(good)]))
        self.assertEqual(verdict, "FAIL")
        self.assertIn("phase 1", reason)
        self.assertIn("secret (console-1.log)", reason)
        ok = dict(ph, console={"port": 1, "received": "x y"})
        self.assertEqual(self.boot(dict(case, phases=[ok, dict(good)]))[0], "PASS")

    def test_every_phase_keeps_its_console_transcript(self):
        # Security review M5: a multi-phase case writes console-<i>.log per phase (as serial-<i>.log),
        # so a later phase's session never overwrites an earlier one's transcript; a case-level
        # forbidden marker names the file it was found in.
        good = {"qemu_extra": self.script(self.GOOD)}
        case = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT, "forbidden_markers": ["leak"],
                "phases": [dict(good, console={"port": 1, "received": "first leak"}),
                           dict(good, console={"port": 2, "received": "second"})]}
        files = {}
        verdict, reason = self.boot(case, files)
        self.assertEqual(files.get("console-1.log"), b"first leak")
        self.assertEqual(files.get("console-2.log"), b"second")
        self.assertNotIn("console.log", files)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("leak (console-1.log)", reason)
        single = {"expected_exit_code": 0, "ends_by": "monitor", "monitor": self.QUIT,
                  "phases": [dict(good, console={"port": 1, "received": "only"})]}
        files = {}
        self.assertEqual(self.boot(single, files)[0], "PASS")
        self.assertEqual(files.get("console.log"), b"only")

    def test_a_retry_after_qemu_died_gets_a_fresh_console_session(self):
        # The auditor's WP-82 limit: QEMU dies by a signal, the phase is retried on a fresh image;
        # the retry needs its own console session, so neither the dead attempt's transcript nor
        # its console failures judge the case.
        script = self.script([("__signal_once__11", 0.1), ("OSX|x|k|phase=1|", 0.2)])   # then exits 33
        case = {"expected_exit_code": 33, "forbidden_markers": ["leak"], "qemu_extra": script,
                "console": {"port": 1, "attempts": [("stale leak", ["console: no prompt from the shell"]), ("fresh", [])]}}
        files = {}
        verdict, reason = self.boot(case, files)
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn("qemu died with signal 11, retried", reason)
        self.assertEqual(files.get("console.log"), b"fresh")

    def test_a_phase_timeout_bounds_that_phase(self):
        import time
        slow = self.script([("boot", 8.0)])           # exits 33 after ~9.5 s
        case = {"expected_exit_code": 33, "phases": [{"qemu_extra": slow, "timeout_s": 2}]}
        begin = time.monotonic()
        verdict, reason = self.boot(case)
        self.assertEqual((verdict, reason), ("FAIL", "timeout (hang)"))
        self.assertLess(time.monotonic() - begin, 7)


class ConsoleReceived(unittest.TestCase):
    """The real ConsoleSession (WP-82) against a TCP peer acting as the guest's shell:
    `received` is every byte the guest sent, a guest line starting `>>> ` included, and none of
    the lab's own `>>> ` lines, which stay in the transcript (console.log)."""

    def test_received_is_the_guests_bytes_only(self):
        import socket
        import threading
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]

        def guest():
            c, _ = srv.accept()
            c.sendall(b"nawah sh 1\nnawah> ")
            buf = b""
            while b"\n" not in buf:
                buf += c.recv(64)
            c.sendall(b"out-of-guest\n>>> guest-forbidden\nnawah> ")
            c.recv(64)
            c.close()
        th = threading.Thread(target=guest, daemon=True); th.start()
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            spec = {"port": port, "script": [{"send": "echo lab-sent", "expect": ["out-of-guest"]}]}
            cs = project.ConsoleSession(spec, td / "console.log", td / "serial.log", 10)
            cs.start()
            cs.thread.join(10)
            failures = cs.finish()
            th.join(5); srv.close()
            self.assertEqual(failures, [])
            self.assertIn(b"out-of-guest", cs.received)
            self.assertIn(b"nawah sh 1", cs.received)
            self.assertNotIn(b"lab-sent", cs.received)
            # Provenance, not prefix (security review L1): a guest line that looks like the
            # lab's own `>>> ` echo is still the guest's and still checked.
            self.assertIn(b">>> guest-forbidden", cs.received)
            self.assertIn(b">>> echo lab-sent", (td / "console.log").read_bytes())


if __name__ == "__main__":
    unittest.main()
