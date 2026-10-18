"""TST-M4-SHELL-TOOL (host): the lab's console session (tools/project.py ConsoleSession,
WP-30) against a fake shell served over TCP the way QEMU serves COM2 — the same banner,
prompts and line protocol as shell.md: the session must wait for the serial marker, split
each command's output from the prompt that follows it, judge literal expectations, prompts,
absent strings and values taken from the serial log, and report every miss by step."""

import pathlib
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import project  # noqa: E402

REPLIES = {
    b"svc": b"auth ready 0 1 1 20 -\nnet ready 0 21 21 30 -\nsh ready 0 31 31 32 -\n",
    b"cpu": b"cpus=4 ticks=1234 processes=4 threads=5\n",
    b"login admin lab-admin-1": b"logged in as admin\n",
    b"logout": b"logged out\n",
    b"nosuch": b"ERR UNKNOWN_COMMAND\n",
}


class FakeShell(threading.Thread):
    """Accepts one client, prints the banner and prompt, answers commands until `exit`."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = []

    def run(self):
        conn, _ = self.sock.accept()
        self.sock.close()
        with conn:
            user = b""
            conn.sendall(b"nawah sh 1 (help)\n" + user + b"nawah> ")
            buf = b""
            while True:
                data = conn.recv(1024)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self.received.append(line)
                    if line == b"exit":
                        conn.sendall(b"bye\n")
                        return
                    reply = REPLIES.get(line, b"")
                    if line.startswith(b"login "):
                        user = line.split()[1] + b"@"
                    if line == b"logout":
                        user = b""
                    conn.sendall(reply + user + b"nawah> ")


class ConsoleSessionTest(unittest.TestCase):
    def session(self, script, serial_text, after="|ready=1"):
        shell = FakeShell()
        shell.start()
        tmp = pathlib.Path(tempfile.mkdtemp())
        serial = tmp / "serial.log"
        serial.write_text(serial_text)
        spec = {"port": shell.port, "after": after, "script": script}
        s = project.ConsoleSession(spec, tmp / "console.log", serial, timeout=20)
        s.start()
        failures = s.finish()
        return shell, failures, (tmp / "console.log").read_bytes()

    def test_passing_session(self):
        script = [
            {"send": "svc", "expect": ["auth ready", "net ready", "sh ready"]},
            {"send": "cpu", "expect": ["cpus="], "expect_serial": [["cpus=", "|ktest|shell_svc|cpus=", "|"]]},
            {"send": "login admin lab-admin-1", "expect": ["logged in as admin"], "prompt": "admin@nawah> "},
            {"send": "logout", "expect": ["logged out"], "prompt": "nawah> "},
            {"send": "nosuch", "expect": ["ERR UNKNOWN_COMMAND"], "absent": ["cpus="]},
            {"send": "exit", "final": True},
        ]
        shell, failures, transcript = self.session(script, "OSX|x|ktest|shell_svc|cpus=4|frames_total=100|ready=1\n")
        self.assertEqual(failures, [])
        self.assertEqual(shell.received, [b"svc", b"cpu", b"login admin lab-admin-1", b"logout", b"nosuch", b"exit"])
        self.assertIn(b">>> cpu\ncpus=4 ticks=1234", transcript)
        self.assertTrue(transcript.endswith(b"bye\n"))

    def test_failures_are_reported_by_step(self):
        script = [
            {"send": "cpu", "expect": ["cpus=8"], "expect_serial": [["cpus=", "|ktest|shell_svc|cpus=", "|"]]},
            {"send": "login admin lab-admin-1", "prompt": "nawah> "},
            {"send": "nosuch", "absent": ["ERR UNKNOWN_COMMAND"]},
            {"send": "exit", "final": True},
        ]
        _, failures, _ = self.session(script, "OSX|x|ktest|shell_svc|cpus=2|frames_total=100|ready=1\n")
        self.assertEqual(len(failures), 4, failures)
        self.assertIn("expected 'cpus=8'", failures[0])
        self.assertIn("expected 'cpus=2' (from the serial log)", failures[1])
        self.assertIn("prompt b'admin@nawah> ' != 'nawah> '", failures[2])
        self.assertIn("forbidden 'ERR UNKNOWN_COMMAND'", failures[3])

    def test_missing_marker_stops_the_session(self):
        script = [{"send": "cpu", "expect": ["cpus="]}, {"send": "exit", "final": True}]
        shell = FakeShell()
        shell.start()
        tmp = pathlib.Path(tempfile.mkdtemp())
        serial = tmp / "serial.log"
        serial.write_text("nothing here\n")
        s = project.ConsoleSession({"port": shell.port, "after": "|ready=1", "script": script}, tmp / "console.log", serial, timeout=3)
        s.start()
        failures = s.finish()
        self.assertTrue(any("never appeared" in f for f in failures), failures)
        self.assertTrue(any("never ran" in f for f in failures), failures)
        self.assertEqual(shell.received, [])


if __name__ == "__main__":
    unittest.main()
