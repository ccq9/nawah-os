"""TST-M0-003 (host, REQ-M0-005): the verification runner's workflow files — every file under
.github/workflows parses as YAML with a name, triggers and jobs (a malformed file is a failed run
on every push: five such runs on 2026-10-18); `verify` runs on pushes to main, pull requests and
by hand, gives its job a time limit, and cancels the run a newer push to the same ref supersedes
(42 of the 59 failed verify runs that day had been superseded within ten minutes and still ran
to their end and mailed the account); `mutants` never runs on a push. The local pre-flight
(`project.py preflight`) builds with build-std from the library source at the compiler's own
commit, with scratch evidence only."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
sys.path.insert(0, str(ROOT / "tools"))
import project  # noqa: E402


def load(name):
    doc = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    # YAML 1.1 reads the bare key `on` as the boolean true.
    doc["on"] = doc.pop(True, doc.get("on"))
    return doc


class Workflows(unittest.TestCase):
    def test_every_workflow_parses(self):
        files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertGreaterEqual(len(files), 2)
        for f in files:
            doc = load(f.name)
            for key in ("name", "on", "jobs"):
                self.assertIn(key, doc, f"{f.name}: no `{key}`")
            for job, body in doc["jobs"].items():
                self.assertIn("runs-on", body, f"{f.name}: job {job} has no runner")
                self.assertTrue(body.get("steps"), f"{f.name}: job {job} has no steps")

    def test_verify_triggers_limit_and_cancellation(self):
        doc = load("verify.yml")
        on = doc["on"]
        self.assertEqual(on["push"]["branches"], ["main"])
        self.assertIn("pull_request", on)
        self.assertIn("workflow_dispatch", on)
        self.assertTrue(all("timeout-minutes" in j for j in doc["jobs"].values()))
        group = doc.get("concurrency", {})
        self.assertIn("${{ github.ref }}", str(group.get("group", "")),
                      "runs of one ref share a concurrency group")
        self.assertIs(group.get("cancel-in-progress"), True,
                      "a newer push cancels the run it supersedes")

    def test_mutants_never_on_push(self):
        on = load("mutants.yml")["on"]
        self.assertNotIn("push", on)
        self.assertIn("workflow_dispatch", on)


class Preflight(unittest.TestCase):
    def test_preflight_runs_the_ci_hygiene_commands(self):
        # The local gate is CI's hygiene step itself, read from verify.yml (CI run 39185115793
        # failed on a clippy configuration the local pre-flight never ran).
        env, cmds = project.hygiene_commands()
        step = next(s for j in load("verify.yml")["jobs"].values() for s in j["steps"]
                    if str(s.get("name", "")).startswith(project.HYGIENE_STEP))
        script = [l.strip() for l in step["run"].splitlines()]
        expected = [l for l in script if l.startswith(("cargo ", "sh tools/"))]
        self.assertEqual(cmds, expected)
        self.assertEqual(env, {str(k): str(v) for k, v in (step.get("env") or {}).items()})
        self.assertIn("cargo fmt --all --check", cmds)
        kernel = [c for c in cmds if "kernel/Cargo.toml" in c]
        self.assertTrue(any("--features" not in c and "x86_64-unknown-uefi" in c for c in kernel),
                        "the production kernel (no ktest) must be linted")
        self.assertTrue(any("--features ktest" in c for c in kernel))
        self.assertTrue(any("aarch64-unknown-uefi" in c for c in kernel))
        self.assertTrue(all("-D warnings" in c for c in cmds if c.startswith("cargo clippy")))
        self.assertIn("sh tools/check-unsafe.sh", cmds)
        # Locally only --offline is dropped; the lint configuration is unchanged.
        c = "cargo clippy --manifest-path kernel/Cargo.toml --target x86_64-unknown-uefi --offline -- -D warnings"
        self.assertEqual(project.local_hygiene_argv(c),
                         ["cargo", "clippy", "--manifest-path", "kernel/Cargo.toml", "--target",
                          "x86_64-unknown-uefi", "--", "-D", "warnings"])
        # And pre-flight runs it, after fmt and before the build.
        import inspect
        src = inspect.getsource(project.cmd_preflight)
        self.assertLess(src.index('"fmt"'), src.index("cmd_hygiene()"))
        self.assertLess(src.index("cmd_hygiene()"), src.index('"build"'))
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "w.yml"
            p.write_text("name: x\njobs:\n  a:\n    runs-on: u\n    steps:\n      - run: echo\n")
            with self.assertRaises(ValueError):
                project.hygiene_commands(p)

    def test_environment(self):
        env = project.preflight_env({"PATH": "/bin", "RUSTUP_TOOLCHAIN": "t"}, "/tmp/scratch", True)
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "t")
        self.assertEqual(env["RUSTC_BOOTSTRAP"], "1")
        self.assertEqual(env["CARGO_UNSTABLE_BUILD_STD"], "core,alloc,compiler_builtins")
        self.assertEqual(env["CARGO_UNSTABLE_BUILD_STD_FEATURES"], "compiler-builtins-mem")
        # Evidence of a pre-flight never reaches the records.
        self.assertEqual(env["NAWAH_SCRATCH_EVIDENCE"], "/tmp/scratch")
        # The test step builds host tools: no build-std there, even when the caller had it.
        test_env = project.preflight_env(env, "/tmp/scratch", False)
        for k in ("RUSTC_BOOTSTRAP", "CARGO_UNSTABLE_BUILD_STD", "CARGO_UNSTABLE_BUILD_STD_FEATURES"):
            self.assertNotIn(k, test_env)
        self.assertEqual(test_env["NAWAH_SCRATCH_EVIDENCE"], "/tmp/scratch")
        self.assertEqual(test_env["PATH"], "/bin")

    def test_library_source_must_match_the_compiler(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "rust"
            self.assertEqual(project.rust_src_state(src, "abc"), "missing")
            (src / "library").mkdir(parents=True)
            (src / "library" / "Cargo.lock").write_text("# lock\n")
            # rustup's rust-src has no git metadata: the same release, trusted.
            self.assertEqual(project.rust_src_state(src, "abc"), "ok")
            run = lambda *a: subprocess.run(["git", "-C", str(src), *a], check=True, capture_output=True, text=True)
            run("init", "-q")
            run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x")
            head = run("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(project.rust_src_state(src, head), "ok")
            self.assertEqual(project.rust_src_state(src, "0" * 40), f"mismatch:{head}")


if __name__ == "__main__":
    unittest.main()
