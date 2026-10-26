"""TST-M0-003 (host, REQ-M0-005): the verification runner's workflow files — every file under
.github/workflows parses as YAML with a name, triggers and jobs (a malformed file is a failed run
on every push: five such runs on 2026-10-18); `verify` runs on pushes to main, pull requests and
by hand, gives its job a time limit, and cancels the run a newer push to the same ref supersedes
(42 of the 59 failed verify runs that day had been superseded within ten minutes and still ran
to their end and mailed the account); `mutants` never runs on a push. The local pre-flight
(`project.py preflight`) builds with build-std from the library source at the compiler's own
commit, with scratch evidence only. `project.py import-ci-evidence` leaves no temporary copy of
the runner's evidence behind."""

import json
import os
import shutil
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

    def test_every_action_is_pinned_to_a_commit(self):
        # A tag can be moved to other code; a commit cannot (the audit of 2026-10-19). The
        # comment after the pin names the release it was taken from.
        for f in sorted(WORKFLOWS.glob("*.yml")):
            for job, body in load(f.name)["jobs"].items():
                for step in body["steps"]:
                    uses = step.get("uses")
                    if uses is None:
                        continue
                    ref = uses.rpartition("@")[2]
                    self.assertRegex(ref, r"^[0-9a-f]{40}$", f"{f.name}: {job} uses {uses}")

    def test_only_the_publish_step_holds_the_token(self):
        # The code under test runs in the same job: the checkout keeps no credentials in
        # .git/config, and the token reaches the evidence push alone.
        for f in sorted(WORKFLOWS.glob("*.yml")):
            text = (WORKFLOWS / f.name).read_text(encoding="utf-8")
            for job, body in load(f.name)["jobs"].items():
                for step in body["steps"]:
                    if step.get("uses", "").startswith("actions/checkout@"):
                        self.assertIs(step.get("with", {}).get("persist-credentials"), False,
                                      f"{f.name}: {job}: checkout keeps the token")
                holders = [s.get("name") for s in body["steps"] if "github.token" in str(s)
                           or "secrets." in str(s)]
                self.assertLessEqual(len(holders), 1, f"{f.name}: {job}: {holders}")
                if holders:
                    self.assertTrue(holders[0].startswith("Publish evidence"), holders)
            self.assertNotIn("secrets.", text, f"{f.name} reads a secret")

    def test_mutants_never_on_push(self):
        on = load("mutants.yml")["on"]
        self.assertNotIn("push", on)
        self.assertIn("workflow_dispatch", on)

    def test_toolchain_downloads_are_bounded_and_retried(self):
        # Runs 39960346156, 39966156761 and 39966899234 (2026-10-23): the Toolchain step, about
        # 80 s on a good day, hung for 34-40 minutes and the job hit its 40-minute limit before
        # any test ran. A download that hangs must fail fast and be tried again, and the step
        # must end long before the job's limit.
        downloads = ("apt-get ", "rustup toolchain install", "rustup target add")
        for name in ("verify.yml", "mutants.yml"):
            for job, body in load(name)["jobs"].items():
                steps = [s for s in body["steps"] if s.get("name", "").startswith("Toolchain")]
                self.assertEqual(len(steps), 1, f"{name}: {job}: one Toolchain step")
                step = steps[0]
                self.assertLessEqual(step.get("timeout-minutes", 10**6), 15,
                                     f"{name}: {job}: the Toolchain step has no short limit")
                run = step["run"]
                self.assertRegex(run, r"retry\(\) \{[^}]*timeout \d+ ",
                                 f"{name}: {job}: no retry with a per-attempt timeout")
                for line in (l.strip() for l in run.splitlines()):
                    if any(d in line for d in downloads) and not line.startswith("retry() {"):
                        self.assertTrue(line.startswith("retry "),
                                        f"{name}: {job}: download not retried: {line}")


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
        # The records come first (CI run 39196967624 failed on a record error alone).
        self.assertLess(src.index("validate_records("), src.index('"fmt"'))
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


class CiEvidenceImport(unittest.TestCase):
    """import-ci-evidence checks the runner's evidence branch out into a temporary directory and
    copies the runs from there: the copy goes when the import ends, whether it succeeds or not
    (2026-10-19: 44 left-over copies, 21 GB, filled the workspace's disk), and the repository's
    index is not touched (work the user had staged stays staged)."""

    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="nawah-import-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        base = self.base
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(base), "TMPDIR": str(base / "tmp"),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        (base / "tmp").mkdir()
        self.git(base, "init", "-q", "--bare", "origin")
        work = base / "work"
        self.git(base, "init", "-q", "work")
        self.run_dir = work / "evidence" / "20260101T000000Z-deadbeef-001"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "verdict.json").write_text(json.dumps({"test_id": "TST-X", "verdict": "PASS"}))
        (self.run_dir / "run.json").write_text(json.dumps({"run_id": self.run_dir.name}))
        self.git(work, "checkout", "-q", "-b", "ci-evidence/42")
        self.git(work, "add", "-A")
        self.git(work, "commit", "-q", "-m", "evidence")
        self.git(work, "push", "-q", str(base / "origin"), "ci-evidence/42")
        # A runner branch without the evidence directory: the import's checkout fails.
        self.git(work, "checkout", "-q", "--orphan", "ci-evidence/43")
        self.git(work, "rm", "-q", "-r", "--cached", "evidence")
        (work / "other").write_text("x")
        self.git(work, "add", "other")
        self.git(work, "commit", "-q", "-m", "no evidence")
        self.git(work, "push", "-q", str(base / "origin"), "ci-evidence/43")
        self.root = base / "root"
        self.git(base, "init", "-q", "root")
        self.git(self.root, "remote", "add", "origin", str(base / "origin"))
        (self.root / "evidence").mkdir()
        (self.root / "staged.txt").write_text("the user's work")
        self.git(self.root, "add", "staged.txt")

    def git(self, cwd, *args):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True)

    def run_import(self, run):
        return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "project.py"), "import-ci-evidence", "--run", run],
                              env={**self.env, "NAWAH_ROOT": str(self.root)}, capture_output=True, text=True)

    def staged(self):
        return self.git(self.root, "diff", "--cached", "--name-only").stdout.split()

    def test_import_leaves_no_temporary_copy(self):
        r = self.run_import("42")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("imported 1 run(s) from CI run 42", r.stdout)
        self.assertTrue((self.root / "evidence" / self.run_dir.name / "verdict.json").exists())
        self.assertEqual(sorted(p.name for p in (self.base / "tmp").iterdir()), [])
        self.assertEqual(self.staged(), ["staged.txt"])

    def test_failed_import_leaves_no_temporary_copy(self):
        r = self.run_import("43")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("fetch failed", r.stdout)  # the checkout, not the fetch, failed
        self.assertEqual(sorted(p.name for p in (self.base / "tmp").iterdir()), [])
        self.assertEqual(self.staged(), ["staged.txt"])


class CheckCommit(unittest.TestCase):
    """DEC-004: a commit whose subject names a work item lands only while that item is active or
    done (OS-EXEC-AR §2.1). The breach it guards against: four WP-43 commits reached main while
    WP-43 was planned (21a979f9, f74a43c9, 1abd1f94, 41224c20). CI runs it on the head commit."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="nawah-commit-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "NAWAH_ROOT": str(self.root)}
        subprocess.run(["git", "init", "-q"], cwd=self.root, env=self.env, check=True)
        (self.root / "docs").mkdir()
        items = [{"id": "WP-01", "status": "active"}, {"id": "WP-02", "status": "planned"}, {"id": "WP-03", "status": "done"}]
        (self.root / "docs" / "work-items.json").write_text(json.dumps({"schema_version": "1.0.0", "records": items}))

    def check(self, subject):
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", subject], cwd=self.root, env=self.env, check=True)
        return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "project.py"), "check-commit"],
                              env=self.env, capture_output=True, text=True)

    def test_a_commit_for_a_planned_item_is_rejected(self):
        for subject, rc in (("WP-01: work", 0), ("WIP WP-01 (1/n): work", 0), ("WP-03 records", 0),
                            ("records: CI run imported", 0), ("checkpoint: x", 0),
                            ("WP-02 M6: early work", 50), ("WIP WP-02 (1/n): early", 50), ("WP-99: unknown", 50)):
            r = self.check(subject)
            self.assertEqual(r.returncode, rc, subject + "\n" + r.stdout + r.stderr)

    def test_ci_runs_it(self):
        steps = [s.get("run", "") for j in load("verify.yml")["jobs"].values() for s in j["steps"]]
        self.assertTrue(any("project.py check-commit" in s for s in steps))


class MutationHarness(unittest.TestCase):
    def test_mutants_build_every_app_the_kernel_embeds_and_the_build_compiles(self):
        # Review 2026-10-19 (M8): the harness kept its own app list; WP-40 added exiter to the
        # kernel's embedded apps and the list did not follow, so every mutant build would fail.
        import re
        sys.path.insert(0, str(ROOT / "tests"))
        import mutants  # noqa: E402
        target = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        built = set(re.findall(r"user/apps/([a-z0-9_]+)/Cargo.toml", json.dumps(target["build"])))
        embedded = set(re.findall(r'^\s*"([a-z0-9_]+)",\s*$', (ROOT / "kernel" / "build.rs").read_text(encoding="utf-8"), re.M))
        self.assertTrue(embedded, "no embedded app list found in kernel/build.rs")
        self.assertEqual(set(mutants.APPS), built)
        self.assertLessEqual(embedded, set(mutants.APPS), "an app the kernel embeds is not built by the harness")
        self.assertEqual(len(mutants.APPS), len(set(mutants.APPS)))


if __name__ == "__main__":
    unittest.main()
