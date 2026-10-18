"""TST-M5-LAB-TOOL (host): the lab's monitor driver (tools/project.py run_qemu_monitored,
WP-27/WP-33) against a fake QEMU — a process that writes serial markers over time and serves
a monitor socket the way QEMU does: every step's commands must be sent once its marker has
appeared, in order, and a later step must not fire on an earlier marker; a single-step
`{after, commands}` case still works; `${SCREEN}` names the run's screendump."""

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
got = []
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
time.sleep(1.5)
sys.exit(33)
'''


class MonitorSteps(unittest.TestCase):
    def drive(self, actions, script, timeout=20):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            serial, mon, record = d / "serial.log", d / "mon.sock", d / "record.json"
            fake = d / "fake_qemu.py"
            fake.write_text(FAKE_QEMU)
            cmd = [sys.executable, "-I", str(fake), str(serial), str(mon), str(record), json.dumps(script)]
            rc = project.run_qemu_monitored(cmd, d, d / "out.log", d / "err.log", timeout, serial, mon, actions)
            got = json.loads(record.read_text()) if record.exists() else []
            return rc, got, (d / "out.log").read_text(), (d / "err.log").read_text()

    def test_single_step(self):
        rc, got, out, err = self.drive({"after": "|ready=1", "commands": ["sendkey a", "screendump ${SCREEN}"]},
                                       [("boot", 0.1), ("OSX|x|ktest|t|ready=1", 0.3)])
        self.assertEqual(rc, 33)
        self.assertEqual(got[0], "sendkey a")
        self.assertTrue(got[1].startswith("screendump ") and got[1].endswith("screen.ppm"), got)
        self.assertIn("sent 2 command(s)", out)
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

    def test_timeout_kills_qemu(self):
        rc, got, _, err = self.drive({"after": "|never|", "commands": ["sendkey a"]}, [("boot", 5.0)], timeout=2)
        self.assertEqual(rc, 124)
        self.assertEqual(got, [])
        self.assertIn("TIMEOUT", err)


if __name__ == "__main__":
    unittest.main()
