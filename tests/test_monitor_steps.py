"""TST-M5-LAB-TOOL (host): the lab's monitor driver (tools/project.py run_qemu_monitored,
WP-27/WP-33) against a fake QEMU — a process that writes serial markers over time and serves
a monitor socket the way QEMU does: every step's commands must be sent once its marker has
appeared, in order, and a later step must not fire on an earlier marker; a single-step
`{after, commands}` case still works; `${SCREEN}` names the run's screendump and
`${SCREEN:tag}` (WP-37) one of several, `screen-<tag>.ppm` beside it, in commands and in
host-check arguments alike. `key-down`/`key-up` (WP-38) go through QMP on one connection kept
for the run: a key pressed in one step is released by a later step, within a bounded delay of
that step's marker."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import project  # noqa: E402

FAKE_QEMU = r'''
import json, socket, sys, time, threading
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
threading.Thread(target=serve, daemon=True).start()
with open(serial, "ab") as f:
    for line, wait in script:
        time.sleep(wait)
        f.write((line + "\n").encode()); f.flush()
        marks[line] = round(time.monotonic() - t0, 3)
time.sleep(1.5)
if qmp_path:
    with open(record + ".qmp", "w") as f:
        json.dump({"qmp": qmp_got, "marks": marks}, f)
sys.exit(33)
'''


class MonitorSteps(unittest.TestCase):
    def drive(self, actions, script, timeout=20):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            serial, mon, record = d / "serial.log", d / "mon.sock", d / "record.json"
            fake = d / "fake_qemu.py"
            fake.write_text(FAKE_QEMU)
            cmd = [sys.executable, "-I", str(fake), str(serial), str(mon), str(record), json.dumps(script),
                   str(project.qmp_socket_path(mon))]
            rc = project.run_qemu_monitored(cmd, d, d / "out.log", d / "err.log", timeout, serial, mon, actions)
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

    def test_timeout_kills_qemu(self):
        rc, got, _, err = self.drive({"after": "|never|", "commands": ["sendkey a"]}, [("boot", 5.0)], timeout=2)
        self.assertEqual(rc, 124)
        self.assertEqual(got, [])
        self.assertIn("TIMEOUT", err)


if __name__ == "__main__":
    unittest.main()
