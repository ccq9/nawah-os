"""TST-M0-003 (host, REQ-M0-005): the verification runner's workflow files — every file under
.github/workflows parses as YAML with a name, triggers and jobs (a malformed file is a failed run
on every push: five such runs on 2026-10-18); `verify` runs on pushes to main, pull requests and
by hand, gives its job a time limit, and cancels the run a newer push to the same ref supersedes
(42 of the 59 failed verify runs that day had been superseded within ten minutes and still ran
to their end and mailed the account); `mutants` never runs on a push. The local pre-flight
(`project.py preflight`) builds with build-std from the library source at the compiler's own
commit, with scratch evidence only. `project.py import-ci-evidence` leaves no temporary copy of
the runner's evidence behind. kernel/src/kmain.rs waits for the service manager's LOAD reply
through `LOAD_BUDGET_TICKS` = 10_000, never a literal (WP-82)."""

import json
import re
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
                # Run 40362082749's healthy Toolchain step took 5 minutes; in run 40367178852 a
                # 240 s attempt limit killed one download three times and failed the job. An
                # attempt must outlast a slow download, all attempts must end inside the step's
                # limit, and each failed attempt leaves an annotation (the logs may be
                # unreadable, the check-run annotations are not).
                m = re.search(r"retry\(\) \{ for i in ([\d ]+); do (?:s=\$SECONDS; )?timeout (\d+) [^}]*sleep (\d+)", run)
                self.assertIsNotNone(m, f"{name}: {job}: retry() not in the expected form")
                attempts, limit, pause = len(m.group(1).split()), int(m.group(2)), int(m.group(3))
                self.assertGreaterEqual(limit, 300, f"{name}: {job}: an attempt dies before a slow download ends")
                self.assertGreaterEqual(attempts, 2, f"{name}: {job}: no second attempt")
                self.assertLessEqual(attempts * limit + (attempts - 1) * pause, step["timeout-minutes"] * 60,
                                     f"{name}: {job}: the attempts outlast the step")
                self.assertIn("::warning", run, f"{name}: {job}: a failed attempt leaves no annotation")
                for line in (l.strip() for l in run.splitlines()):
                    if any(d in line for d in downloads) and not line.startswith("retry() {"):
                        self.assertTrue(line.startswith(("retry ", "if ! retry ")),
                                        f"{name}: {job}: download not retried: {line}")
                # Runs 40397445659 and 40397458355 (2026-10-26, 20:38-21:11): `apt-get install`
                # hit its limit in all four attempts while the same commit's step had taken a
                # minute at 20:10. Each failed attempt says how it ended and how much it had
                # fetched; packages are fetched apart from their installation so a second attempt
                # keeps what the first one got; when the runner's mirror fails twice the packages
                # come from Canonical's archive; nothing may wait for an answer on a terminal.
                self.assertRegex(run, r"rc=\$rc", f"{name}: {job}: the annotation omits the exit code")
                self.assertIn("/var/cache/apt/archives", run,
                              f"{name}: {job}: the annotation omits how much was fetched")
                lines = [l.strip() for l in run.splitlines()]
                fetch = [i for i, l in enumerate(lines) if "apt-get " in l and " install --download-only " in l]
                install = [i for i, l in enumerate(lines) if "apt-get " in l and " install " in l
                           and "--download-only" not in l]
                self.assertTrue(fetch and install and max(fetch) < min(install),
                                f"{name}: {job}: packages are not fetched before they are installed")
                self.assertIn("archive.ubuntu.com", run, f"{name}: {job}: no fallback mirror")
                for i in fetch + install:
                    self.assertIn("DEBIAN_FRONTEND=noninteractive", lines[i],
                                  f"{name}: {job}: apt may wait for an answer: {lines[i]}")

    def test_a_rerun_replaces_the_published_evidence(self):
        # Run 40397458355, attempt 2: the evidence branch of the first attempt already existed and
        # the plain push was refused, so the step failed. A re-run's evidence replaces it.
        step = next(s for j in load("verify.yml")["jobs"].values() for s in j["steps"]
                    if str(s.get("name", "")).startswith("Publish evidence"))
        push = [l for l in step["run"].splitlines() if " push " in l]
        self.assertEqual(len(push), 1)
        self.assertRegex(push[0], r" push (-q )?(-f|--force) ", "a re-run cannot replace the evidence branch")


class Suites(unittest.TestCase):
    """The lab and the workflow name the same suites (docs/PLAN-ANSWER.md §2.5 D5): every guest
    suite of platform/pc-qemu/target.json has its verify step and every verify step names a
    suite that exists; every host suite the workflow does not run by design (the mutation gates,
    M2 whose host suite is its gate) is excluded by name, every other one is non-empty and run."""

    def steps(self):
        return [s for job in load("verify.yml")["jobs"].values() for s in job["steps"]]

    def suite_args(self, kind):
        """The suites a step names: `--suite X` literally, or `--suite "$v"` inside a
        `for v in X Y …; do` loop of the same step (WP-91)."""
        found = set()
        for s in self.steps():
            run = str(s.get("run", ""))
            for line in run.splitlines():
                m = re.search(rf"--target {kind} --suite (\S+)", line)
                if not m:
                    continue
                var = re.fullmatch(r'"?\$\{?(\w+)\}?"?;?', m.group(1))
                if var:
                    loop = re.search(rf"\bfor {var.group(1)} in ([^;\n]+);", run)
                    found.update(loop.group(1).split() if loop else [m.group(1)])
                else:
                    found.add(m.group(1))
        return found

    def test_every_guest_suite_runs_in_verify(self):
        target = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(target["suites"]), sorted(self.suite_args("pc-qemu")))

    def test_every_host_suite_is_nonempty_and_runs_in_verify(self):
        excluded = {"M2"}  # its host suite is the M2 mutation gate, run by the mutants workflow
        expected = {k for k in project.HOST_SUITES if not k.endswith("-GATE") and k not in excluded}
        self.assertEqual([k for k in expected if not project.HOST_SUITES[k]], [])
        self.assertEqual(sorted(expected), sorted(self.suite_args("host")))


class HostStep(unittest.TestCase):
    """WP-91: the Host suites step runs every host suite the workflow runs (every non-gate suite
    of HOST_SUITES but M2) and reports every failure: a failing suite does not end the step
    before the later ones run (six bare commands under `bash -e` did: runs 42769555412,
    42790269224 and 42795169926 hid the later suites' verdicts), and the step fails at the end
    when any suite failed. Judged by running the step's own script the way GitHub runs a step
    without `shell:` (`bash -e {0}`: no pipefail, so a suite piped into `tee` would hide its
    failure) in a scratch tree whose tools/project.py is a stub that records each suite and
    fails the chosen ones; found in whichever verify job holds it."""

    EXPECTED = sorted(k for k in project.HOST_SUITES if not k.endswith("-GATE") and k != "M2")

    def step(self):
        steps = [s for job in load("verify.yml")["jobs"].values() for s in job["steps"]
                 if str(s.get("name", "")) == "Host suites"]
        self.assertEqual(len(steps), 1, "one Host suites step")
        return steps[0]

    def run_step(self, failing, script=None):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "tools").mkdir()
        (d / "tools" / "project.py").write_text(
            "import os, sys\n"
            "suite = sys.argv[sys.argv.index('--suite') + 1]\n"
            "open('suites.log', 'a').write(suite + '\\n')\n"
            "sys.exit(1 if suite in os.environ['FAILING'].split() else 0)\n")
        (d / "step.sh").write_text(self.step()["run"] if script is None else script)
        # GitHub's default for a run step without `shell:` on Linux: bash -e {0}.
        r = subprocess.run(["bash", "-e", str(d / "step.sh")], cwd=d,
                           capture_output=True, text=True, env=dict(os.environ, FAILING=" ".join(failing)))
        ran = (d / "suites.log").read_text().split() if (d / "suites.log").exists() else []
        return r.returncode, ran

    def problems(self, script=None):
        """What the step (or `script`) breaks: a suite not run, run twice, or a red set that
        passes; an empty list when it runs every suite and fails exactly when one failed."""
        bad = []
        rc, ran = self.run_step([], script)
        if rc != 0 or sorted(ran) != self.EXPECTED:
            bad.append(f"nothing failing: exit {rc}, ran {ran}")
        if len(ran) != len(set(ran)):
            bad.append(f"a suite ran twice: {ran}")
        first, last = self.EXPECTED[0], self.EXPECTED[-1]
        for failing in ([first], [first, last], [last], self.EXPECTED):
            rc, ran = self.run_step(failing, script)
            if sorted(ran) != self.EXPECTED:
                bad.append(f"failing {failing}: the step stopped early, ran {ran}")
            if rc == 0:
                bad.append(f"failing {failing}: the step passed")
        return bad

    def test_the_step_runs_every_suite_and_fails_when_any_failed(self):
        self.assertEqual(self.problems(), [])

    def test_the_check_sees_a_failure_hidden_by_a_pipe(self):
        # The auditor's survivor: under bash -e without pipefail a pipeline's status is its last
        # command's, so `… --suite "$s" | tee -a host.log || rc=1` never records a failure.
        loop = ('rc=0\nfor s in {}; do\n  python3 tools/project.py test --target host --suite "$s"{} || rc=1\n'
                'done\nexit $rc\n')
        self.assertEqual(self.problems(loop.format(" ".join(self.EXPECTED), "")), [])
        bad = self.problems(loop.format(" ".join(self.EXPECTED), " | tee -a host.log"))
        self.assertTrue(any("the step passed" in b for b in bad), bad)
        bare = "".join(f"python3 tools/project.py test --target host --suite {s}\n" for s in self.EXPECTED)
        self.assertTrue(any("stopped early" in b for b in self.problems(bare)))


class MergeJob(unittest.TestCase):
    """WP-83 (83a; ADR-0026 rule 5 as WP-81 amends it): verify's test jobs each write run
    directories with their own slot (NAWAH_RUN_SLOT, one distinct lowercase letter) and upload
    only those (`evidence/*-<slot>/`) as the artifact `evidence-<slot>`; one `merge` job, which
    needs every other job and runs unless the run was cancelled (a superseded run never
    publishes), downloads them through a pinned action, adopts them with `adopt-native --from`,
    then runs the strict validator and tools/pre-merge.sh, and alone publishes the run's one
    ci-evidence branch: only when the adoption succeeded, also after a failed test job or a red
    strict check (what exists is published, the run still fails: import-ci-evidence refuses a
    run that did not succeed), and it fails the run when any test job did not succeed. No test
    job validates strictly or publishes (a strict check inside one job sees the other jobs'
    fresh verdicts as stale). The workflow's token reads; only the publishing job may write."""

    def jobs(self):
        return load("verify.yml")["jobs"]

    def merge(self):
        jobs = self.jobs()
        self.assertIn("merge", list(jobs), "verify has no merge job")
        return jobs["merge"]

    @staticmethod
    def index(steps, pred, what):
        found = [i for i, s in enumerate(steps) if pred(s)]
        assert len(found) == 1, f"{what}: {len(found)} steps"
        return found[0]

    def test_the_merge_job_needs_every_test_job_and_skips_a_cancelled_run(self):
        jobs, merge = self.jobs(), self.merge()
        needs = merge.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        self.assertEqual(sorted(needs), sorted(k for k in jobs if k != "merge"))
        self.assertIn("!cancelled()", str(merge.get("if", "")))
        self.assertNotIn("always()", str(merge.get("if", "")))

    def test_the_merge_steps_run_in_order(self):
        steps = self.merge()["steps"]
        run = lambda s: str(s.get("run", ""))
        order = [self.index(steps, lambda s: str(s.get("uses", "")).startswith("actions/download-artifact@"), "download"),
                 self.index(steps, lambda s: "project.py adopt-native" in run(s) and "--from" in run(s), "adopt"),
                 self.index(steps, lambda s: "validate-records --strict" in run(s), "strict"),
                 self.index(steps, lambda s: "tools/pre-merge.sh" in run(s), "pre-merge"),
                 self.index(steps, lambda s: str(s.get("name", "")).startswith("Publish evidence"), "publish")]
        self.assertEqual(order, sorted(order), "download, adopt, strict, pre-merge, publish")
        download = steps[order[0]]
        self.assertEqual(download.get("with", {}).get("pattern"), "evidence-*")
        self.assertFalse(download.get("with", {}).get("merge-multiple", False), "each job's artifact in its own directory")
        adopt, publish = steps[order[1]], steps[order[4]]
        # Publish what exists: after a failed strict check too, never after a failed adoption
        # nor in a cancelled run.
        cond = str(publish.get("if", ""))
        self.assertIn("!cancelled()", cond)
        self.assertIn(f"steps.{adopt.get('id')}.outcome == 'success'", cond)
        self.assertTrue(adopt.get("id"), "the adopt step has an id the publish step can test")
        # The run fails when a test job did not succeed, after the publish.
        last = steps[-1]
        self.assertGreater(len(steps) - 1, order[4])
        self.assertIn("needs.*.result", str(last.get("if", "")))
        self.assertIn("!cancelled()", str(last.get("if", "")))
        self.assertIn("exit 1", run(last))

    def test_no_test_job_validates_strictly_or_publishes(self):
        for name, job in self.jobs().items():
            if name == "merge":
                continue
            for s in job["steps"]:
                run = str(s.get("run", ""))
                self.assertNotIn("validate-records --strict", run, name)
                self.assertNotIn("pre-merge.sh", run, name)
                self.assertNotIn("adopt-native", run, name)
                self.assertFalse(str(s.get("name", "")).startswith("Publish"), name)

    @staticmethod
    def slot_problems(jobs):
        """({job: slot}, problems) of the test jobs' slots and evidence uploads."""
        slots, bad = {}, []
        for name, job in jobs.items():
            if name == "merge":
                continue
            slot = str(job.get("env", {}).get("NAWAH_RUN_SLOT", ""))
            if not project.RUN_SLOT_RE.fullmatch(slot) or not re.fullmatch(r"[a-z]", slot):
                bad.append(f"{name}: NAWAH_RUN_SLOT {slot!r}")
                continue
            if slot in slots.values():
                bad.append(f"{name}: slot {slot} taken by another job")
            slots[name] = slot
            ups = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@")
                   and s.get("with", {}).get("name") == f"evidence-{slot}"]
            if len(ups) != 1:
                bad.append(f"{name}: {len(ups)} uploads of evidence-{slot}")
                continue
            up = ups[0]
            paths = str(up["with"].get("path", "")).split()
            # Exactly the slot's run directories under evidence/, nothing wider (the auditor, 83a).
            ev = [x for x in paths if x.startswith("evidence")]
            if ev != [f"evidence/*-{slot}/"]:
                bad.append(f"{name}: evidence paths {ev}, not exactly ['evidence/*-{slot}/']")
            if "always()" not in str(up.get("if", "")) or up.get("continue-on-error") is not True:
                bad.append(f"{name}: the upload is not always() with continue-on-error")
        if not slots:
            bad.append("no test job")
        return slots, bad

    def test_every_test_job_writes_and_uploads_its_own_slot(self):
        self.assertEqual(self.slot_problems(self.jobs())[1], [])

    def test_an_upload_beyond_the_slots_run_directories_is_refused(self):
        # The auditor (83a): `evidence/*` beside `evidence/*-a/` uploads the whole tree again.
        for extra in ("evidence/*", "evidence", "evidence/**", "evidence/*-b/"):
            jobs = load("verify.yml")["jobs"]
            up = next(s for s in jobs["a"]["steps"] if s.get("with", {}).get("name") == "evidence-a")
            up["with"]["path"] = up["with"]["path"] + extra + "\n"
            self.assertTrue(self.slot_problems(jobs)[1], f"{extra!r} accepted")

    def adopt_step(self):
        return next(s for s in self.merge()["steps"] if s.get("id") == "adopt")

    def run_adopt(self, layout, adopt_rc=0, script=None):
        """Runs the adopt step's script in a scratch tree: `layout` maps a slot to None (no
        artifact), "empty" (no run directory) or the set of parts it holds ({"run", "build"});
        tools/project.py is a stub recording its arguments and exiting `adopt_rc`; `script`
        replaces the step's own. (exit code, output, arguments, tree)."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "tools").mkdir()
        (d / "tools" / "project.py").write_text("import json, sys\nopen('adopt-args', 'w').write(json.dumps(sys.argv[1:]))\n"
                                                f"sys.exit({adopt_rc})\n")
        for slot, parts in layout.items():
            if parts is None:
                continue
            art = d / "incoming" / f"evidence-{slot}"
            (art / "evidence").mkdir(parents=True)
            if parts != "empty" and "run" in parts:
                run = art / "evidence" / f"20261110T000000Z-abcdef12-001-{slot}"
                run.mkdir()
                (run / "verdict.json").write_text("{}")
            if parts != "empty" and "build" in parts:
                (art / "build" / "pc-qemu").mkdir(parents=True)
                (art / "build" / "pc-qemu" / "build-id.txt").write_text(slot)
        (d / "step.sh").write_text(self.adopt_step()["run"] if script is None else script)
        # GitHub's default for a run step without `shell:` on Linux: bash -e {0}.
        r = subprocess.run(["bash", "-e", str(d / "step.sh")], cwd=d, capture_output=True, text=True)
        args = json.loads((d / "adopt-args").read_text()) if (d / "adopt-args").exists() else None
        return r.returncode, r.stdout + r.stderr, args, d

    def test_the_adopt_step_names_every_expected_slot_and_fails_closed(self):
        # Security review M2: a missing slot artifact fails the merge job (the producer's upload
        # stays continue-on-error); no warn-and-skip path, no glob over whatever arrived.
        expected = sorted(self.slot_problems(self.jobs())[0].values())
        run = self.adopt_step()["run"]
        loops = re.findall(r"for slot in ([a-z ]+); do", run)
        # The adoption loop and the build-file copy loop name the same expected slots (G7).
        self.assertEqual(len(loops), 2, "the adopt step does not name its slots in both loops")
        for names in loops:
            self.assertEqual(sorted(names.split()), expected)
        self.assertNotIn("::warning", run)
        self.assertNotIn("incoming/*/evidence", run)
        full = {slot: {"run", "build"} for slot in expected}
        rc, out, args, d = self.run_adopt(full)
        self.assertEqual(rc, 0, out)
        self.assertEqual(args, ["adopt-native"] + [x for slot in expected for x in ("--from", f"incoming/evidence-{slot}/evidence")])
        self.assertTrue((d / "build" / "pc-qemu" / "build-id.txt").exists())
        for slot in expected:
            for broken in (None, "empty"):
                rc, out, args, _ = self.run_adopt(dict(full, **{slot: broken}))
                self.assertNotEqual(rc, 0, f"slot {slot} {broken}: {out}")
                self.assertIn("::error", out)
                self.assertIn(f"evidence-{slot}", out)
                self.assertIsNone(args, "adopt-native ran on a partial set")

    def test_a_failed_adoption_fails_the_adopt_step(self):
        # The auditor's survivor: `adopt-native "${srcs[@]}" || true` let a refused adoption count
        # as success, and Publish runs on the adopt step's success.
        expected = sorted(self.slot_problems(self.jobs())[0].values())
        full = {slot: {"run", "build"} for slot in expected}
        rc, out, args, _ = self.run_adopt(full, adopt_rc=1)
        self.assertIsNotNone(args, "adopt-native never ran")
        self.assertNotEqual(rc, 0, f"a refused adoption passed the step: {out}")
        masked = self.adopt_step()["run"].replace('adopt-native "${srcs[@]}"', 'adopt-native "${srcs[@]}" || true')
        self.assertNotEqual(masked, self.adopt_step()["run"])
        self.assertEqual(self.run_adopt(full, adopt_rc=1, script=masked)[0], 0, "the survivor is no longer one")

    def test_a_source_without_build_files_does_not_fail_the_adopt_step(self):
        # The auditor (83a): `[ -d "$b" ] && cp …` as the loop's last command returned 1 for a
        # source without build/, failing the step after a successful adoption.
        expected = sorted(self.slot_problems(self.jobs())[0].values())
        rc, out, args, _ = self.run_adopt({slot: {"run"} for slot in expected})
        self.assertEqual(rc, 0, out)
        self.assertIsNotNone(args)

    def test_the_publish_step_is_hardened(self):
        # Security review M1 (correction 2): the token's base64 is masked as soon as it exists;
        # git is the system binary, reads no global or system config, runs no hook, traces
        # nothing; the step runs only after a successful adoption in a run not cancelled. (The
        # rule that no repository code runs before Publish in the token's job is WP-89's.)
        pub = next(s for s in self.merge()["steps"] if str(s.get("name", "")).startswith("Publish evidence"))
        self.assertIn("steps.adopt.outcome == 'success'", str(pub.get("if", "")))
        self.assertRegex(str(pub.get("if", "")), r"^\$\{\{.*\}\}$")
        env = pub.get("env", {})
        self.assertEqual(str(env.get("GIT_CONFIG_GLOBAL")), "/dev/null")
        self.assertEqual(str(env.get("GIT_CONFIG_NOSYSTEM")), "1")
        lines = [l.strip() for l in pub["run"].splitlines() if l.strip() and not l.strip().startswith("#")]
        auth = next(i for i, l in enumerate(lines) if l.startswith("auth="))
        self.assertEqual(lines[auth + 1], 'echo "::add-mask::$auth"')
        unset = next(i for i, l in enumerate(lines) if l.startswith("unset "))
        self.assertTrue({"GIT_TRACE", "GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_TRACE_REDACT", "GIT_TRACE_PACKET",
                         "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF"} <= set(lines[unset].split()[1:]), lines[unset])
        gits = [l for l in lines if re.search(r"(^|[\s;|&(])(/usr/bin/)?git\s", l)]
        self.assertTrue(gits)
        for l in gits:
            self.assertTrue(l.startswith("/usr/bin/git -c core.hooksPath=/dev/null "), l)
        push = next(i for i, l in enumerate(lines) if " push " in l)
        self.assertLess(unset, push)
        self.assertLess(auth + 1, push)

    def test_the_token_reads_and_only_the_publishing_job_writes(self):
        doc = load("verify.yml")
        self.assertEqual(doc.get("permissions"), {"contents": "read"})
        for name, job in doc["jobs"].items():
            publishes = any(str(s.get("name", "")).startswith("Publish evidence") for s in job["steps"])
            perms = job.get("permissions", {})
            if publishes:
                self.assertEqual(perms, {"contents": "write"}, name)
            else:
                self.assertNotIn("write", str(perms), name)

class StepBudget(unittest.TestCase):
    """Each verify job's time budget (docs/PLAN-ANSWER.md §2.5 D4-V2; per job since WP-83): the
    guest suites that can hang until the job's limit carry their own cap (M5: 11m34s measured,
    cap 18; M6: cap 15 since WP-64), every job has one Toolchain step capped at 15, and in every
    job the sum of its step caps with a 20 % margin stays within that job's limit (test job `a`
    58: Toolchain 15 + M5 18 + M6 15 = 48, x1.2 = 57.6; WP-74; the merge job 20: Toolchain 15,
    x1.2 = 18), so a hung step ends with its own name instead of the job's timeout. A capped
    suite whose cases are bounded by their own timeouts (M6) must fit its cap in the worst case:
    the sum over its cases of each phase's timeout_s stays below the cap. M5 is outside that
    rule: its cap is a hang guard set from a measured run (its worst case is 33 cases of up to
    300 s each), not a bound on its timeouts. The budget only sees steps that carry a cap: an
    uncapped step (the build, M1-M4, the host suites) runs until the job's limit (G9)."""

    BOUNDED = ("M6",)
    # WP-83 (83a): the test job `a` is the former single job; the merge job adopts and publishes.
    # WP-88 (83b) splits `a` into a, b, c of 40 minutes each.
    LIMITS = {"a": 58, "merge": 20}
    CAPS = {"a": {"M5": 18, "M6": 15}, "merge": {}}

    def caps(self):
        jobs = load("verify.yml")["jobs"]
        caps = {}
        for name, job in jobs.items():
            caps[name] = {}
            for s in job["steps"]:
                for line in str(s.get("run", "")).splitlines():
                    m = re.search(r"--target pc-qemu --suite (\S+)", line)
                    if m and s.get("timeout-minutes") is not None:
                        caps[name][m.group(1)] = s["timeout-minutes"]
        return jobs, caps

    def test_guest_steps_are_capped_within_the_job_limit(self):
        jobs, caps = self.caps()
        # 55 -> 58 and Toolchain 12 -> 15 (WP-74, 2026-11-10): the Toolchain step measured 11m12s
        # on run 42754423494 against its 12-min cap; 15 is a hang guard and 58 keeps the 20 % margin.
        self.assertEqual({k: j.get("timeout-minutes") for k, j in jobs.items()}, self.LIMITS)
        # M6 12 -> 15 (WP-64, 2026-11-10): PURGE-FAIL-CLOSED, TOKEN-REVOKE and WP-46's JOB-KILL
        # bring its worst case under its cap (test_a_bounded_suite_fits_its_cap_in_the_worst_case: the
        # sum of target.json's phase timeouts, 895 s against 900 on 2026-11-14).
        self.assertEqual(caps, self.CAPS)
        for name, job in jobs.items():
            toolchain = [s for s in job["steps"] if str(s.get("name", "")).startswith("Toolchain")]
            self.assertEqual([s.get("timeout-minutes") for s in toolchain], [15], name)
            total = sum(int(s["timeout-minutes"]) for s in job["steps"] if "timeout-minutes" in s)
            self.assertLessEqual(total * 1.2, job["timeout-minutes"],
                                 f"{name}: step caps {total} min + 20 % exceed the job's limit")

    def test_a_bounded_suite_fits_its_cap_in_the_worst_case(self):
        _, per_job = self.caps()
        caps = {suite: cap for job in per_job.values() for suite, cap in job.items()}
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        default = t["qemu"]["boot_timeout_s"]
        for suite in self.BOUNDED:
            worst = sum(p.get("timeout_s", c.get("timeout_s", default))
                        for c in t["suites"][suite] for p in (c.get("phases") or [{}]))
            self.assertLess(worst, caps[suite] * 60, f"{suite}: worst case {worst} s, cap {caps[suite]} min")


class HoldFailClosed(unittest.TestCase):
    """WP-67 (display.md v1.12): TST-M6-HOLD-FAIL-CLOSED runs in the M6 verify step on the test
    image with its ktest key, inside the step's cap (StepBudget), and judges each failure branch
    of displayd's LIST by the compositor's own trace and by the held screen: every branch named
    by the contract is required held (locked=1) and its unheld line is forbidden, so a fail-open
    regression (mutant M147) fails the case."""

    CASE = "TST-M6-HOLD-FAIL-CLOSED"
    KEY = ["-fw_cfg", "name=opt/nawah/test,string=hold_fail_closed"]
    HELD = ["display|hold|source=list_failure|reason=reply|locked=1",
            "display|hold|source=list_failure|reason=too_long|locked=1",
            "display|hold|source=list_failure|reason=closed|locked=1",
            "display|hold|source=manifest|reason=-|locked=0",
            "display|hold|source=manifest|reason=-|locked=1"]
    # The ktest's own verdict lines (kernel/src/ktest.rs hold_fail_closed): the kernel cannot see
    # SYS_TRACE output, so these judge the screen (HOLDS, keys at the client) and the trace lines
    # above judge displayd's decision.
    VERDICTS = ["|ktest|hold_fail_closed|case=reply|holds=OK locked=1 releases=0|keys=0|keys_in=2|",
                "|ktest|hold_fail_closed|case=too_long|holds=OK locked=1 releases=0|keys=0|keys_in=2|",
                "|ktest|hold_fail_closed|case=closed|holds=none_no_ready|exit=0xe6|ok=1",
                "|ktest|hold_fail_closed|case=manifest|locked=0|locked_with_session=1|",
                "|ktest|hold_fail_closed|failed=|processes_after=0|clean=1|frames_delta=0"]
    UNHELD = ["holds=OK locked=0", "reason=reply|locked=0", "reason=too_long|locked=0"]

    def test_the_hold_case_runs_on_the_test_image_in_m6(self):
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        cases = [c for c in t["suites"]["M6"] if c["id"] == self.CASE]
        self.assertEqual(len(cases), 1, f"{self.CASE} is not one case of suites.M6")
        c = cases[0]
        self.assertEqual(c["test_id"], self.CASE)
        self.assertEqual(c["artifact"], "${OUT}/NAWAH-KTEST.EFI")
        self.assertEqual(c["qemu_extra"], self.KEY)
        self.assertEqual(c["expected_exit_code"], 33)
        self.assertEqual(c["timeout_s"], 60)  # measured 8 s on CI; WP-64 moved 120 s of the M6 cap to PURGE-FAIL-CLOSED
        self.assertIn("OSX|${BUILD_ID}|ktest|start|name=hold_fail_closed", c["required_markers"])
        for m in self.HELD + self.VERDICTS + ["|ktest|pass|"]:
            self.assertIn(m, c["required_markers"])
        for m in self.UNHELD + ["|ktest|fail|", "|kernel|panic|"]:
            self.assertIn(m, c["forbidden_markers"])
        # No required marker may also be forbidden (a case that can never pass).
        self.assertEqual([m for m in c["required_markers"] if any(f in m for f in c["forbidden_markers"])], [])


class BootCase(unittest.TestCase):
    """`project.py boot` and the suite judge one boot test by one oracle (docs/PLAN-ANSWER.md
    §2.6 D1-A): the suite case carrying the boot test id is the oracle even when it carries
    QEMU arguments (the lab self-test key, WP-45); two such cases are ambiguous and refused;
    `boot_oracle` carries the same key; the key's name is the one the kernel reads."""

    KEY = ["-fw_cfg", "name=opt/nawah/selftest,string=1"]

    def target(self):
        return json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))

    def test_the_suite_case_with_qemu_args_is_the_boot_oracle(self):
        t = {"boot_oracle": {"test_id": "B"}, "suites": {"S": [{"id": "x", "test_id": "A"},
                                                                {"id": "b", "test_id": "B", "qemu_extra": self.KEY}]}}
        self.assertEqual(project.select_boot_case(t)["id"], "b")
        self.assertIsNone(project.select_boot_case({"boot_oracle": {"test_id": "B"}}))

    def test_two_cases_of_the_boot_test_are_refused(self):
        t = {"boot_oracle": {"test_id": "B"}, "suites": {"S": [{"id": "b1", "test_id": "B"}],
                                                         "T": [{"id": "b2", "test_id": "B", "qemu_extra": self.KEY}]}}
        with self.assertRaises(ValueError):
            project.select_boot_case(t)

    def test_boot_oracle_carries_the_suite_cases_key(self):
        t = self.target()
        case = project.select_boot_case(t)
        self.assertEqual(case["test_id"], "TST-M1-BOOT")
        self.assertEqual(case.get("qemu_extra"), self.KEY)
        self.assertEqual(t["boot_oracle"].get("qemu_extra"), case["qemu_extra"])

    def test_the_kernel_reads_the_key_the_lab_passes(self):
        name = self.KEY[1].split(",", 1)[0].split("=", 1)[1]
        # The test kernel's own sources (ktest.rs) do not count: the release kernel must read it.
        hits = [p for p in (ROOT / "kernel" / "src").rglob("*.rs")
                if p.name != "ktest.rs" and name in p.read_text(encoding="utf-8")]
        self.assertTrue(hits, f"no kernel source outside ktest.rs names the fw_cfg key {name!r}")

    # The boot-mode line as the kernel prints it (kernel/src/kmain.rs: `OSX|<build id>|kernel|
    # boot_mode|<BootMode>`; kernel/src/bootmode.rs Display: source=fw_cfg only for selftest,
    # so an invalid key and a missing signature both print source=none).
    LINE = "OSX|${BUILD_ID}|kernel|boot_mode|mode=%s|source=%s|key=%s|hv=%d"
    PHASES = [("interactive", "none", "absent", 1),    # 1: no key
              ("interactive", "none", "invalid", 1),   # 2: selftest=0
              ("interactive", "none", "absent", 1),    # 3: the ktest key alone
              ("interactive", "none", "invalid", 1),   # 4: selftest=svc-sh
              ("interactive", "none", "absent", 0),    # 5: -hypervisor with the key
              ("interactive", "none", "invalid", 1)]   # 6: selftest=10

    def test_every_boot_requires_its_whole_boot_mode_line(self):
        """Anti-spoofing (WP-45 red team): SYS_TRACE needs no right, so a process can print any
        fragment (`|key=invalid|`, `|hv=0`). Each phase requires the kernel's whole line with the
        build id instead, and the case caps `|kernel|boot_mode|` at one per boot: a traced copy of
        the whole line contains that marker, so it makes a seventh occurrence and fails the case
        (a traced line cannot hold a newline either: syscall/mod.rs prints 0x0A as '?')."""
        t = self.target()
        case = next(c for c in t["suites"]["M6"] if c["id"] == "TST-M6-INTERACTIVE-BOOT")
        self.assertEqual(len(case["phases"]), len(self.PHASES))
        for i, (ph, want) in enumerate(zip(case["phases"], self.PHASES), 1):
            line = self.LINE % want
            mode_markers = [m for m in ph["required_markers"] if "boot_mode" in m or "|key=" in m or "|hv=" in m]
            self.assertEqual(mode_markers, [line], f"phase {i}")
        self.assertEqual(case["max_counts"].get("|kernel|boot_mode|"), len(self.PHASES))
        self.assertEqual(case["min_counts"].get("|kernel|boot_mode|"), len(self.PHASES))
        boot = project.select_boot_case(t)
        mode_markers = [m for m in boot["required_markers"] if "boot_mode" in m]
        self.assertEqual(mode_markers, [self.LINE % ("selftest", "fw_cfg", "ok", 1)])
        # The lab resolves ${BUILD_ID} in a phase's markers and in the case's (cmd_boot).
        src = (ROOT / "tools" / "project.py").read_text(encoding="utf-8")
        self.assertIn('req = [m.replace("${BUILD_ID}", build_id) for m in ph.get("required_markers", [])]', src)
        self.assertIn('required = [m.replace("${BUILD_ID}", build_id) for m in case["required_markers"]]', src)



# WP-82 (boot.md, the interactive LOAD budget): the boot thread waits for the service manager's
# LOAD reply through one named constant of 10_000 ticks (measured waits up to 1096 ticks on CI
# run 42696067096 against the former literal 2000), never a literal at the call. The guard reads
# code, not text: comments and string literals are dropped first, so neither a commented call nor
# a string can stand in for the real one (security review M4).
LOAD_BUDGET_VALUE = 10_000
LOAD_CALLER = "kernel/src/kmain.rs"
LOAD_CALLEE = "kernel/src/services.rs"
TIMER_FILE = "kernel/src/arch/x86_64/irq.rs"
TIMER_HZ_VALUE = 1000
_RAW = re.compile(r'b?r(#*)"')
_CHAR = re.compile(r"b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'")


def rust_code(src):
    """Rust source without its comments (`//`, nested `/* */`) and with every string and char
    literal emptied; the rest, line breaks included, is kept."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    out.append("\n") if src[i] == "\n" else None
                    i += 1
            out.append(" ")
            continue
        ident_before = i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")
        m = None if ident_before else _RAW.match(src, i)
        if m:
            end = src.find('"' + m.group(1), m.end())
            i = n if end < 0 else end + 1 + len(m.group(1))
            out.append('""')
            continue
        if src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            out.append('""')
            continue
        m = _CHAR.match(src, i) if src[i] == "'" else None
        if m:
            out.append("' '")
            i = m.end()
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def kernel_sources(root):
    root = pathlib.Path(root)
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((root / "kernel" / "src").rglob("*.rs"))}


def fn_body(code, name):
    """The body of `fn <name>` in `code` (comments already dropped), braces matched; None if absent."""
    m = re.search(rf"\bfn\s+{name}\s*\(", code)
    if not m:
        return None
    i = code.find("{", m.end())
    depth, j = 0, i
    while j < len(code):
        depth += {"{": 1, "}": -1}.get(code[j], 0)
        if depth == 0:
            return code[i:j + 1]
        j += 1
    return code[i:]


def load_budget_violations(files):
    """What the kernel's sources ({path: text}) break of the LOAD-budget rule:
    - exactly one declaration of LOAD_BUDGET_TICKS in the whole kernel, at any indentation and
      under any attribute, and it is `const LOAD_BUDGET_TICKS: u64 = 10_000;`;
    - start_at_boot is defined once (services.rs) and named exactly once elsewhere: one call in
      kmain.rs whose first argument is the identifier LOAD_BUDGET_TICKS; any other mention (a
      second call, a `use … as` alias, a function pointer) is reported;
    - inside start_at_boot its tick parameter is used once, as the deadline `t0 + timeout_ticks`
      (no clamp, no rebinding);
    - the timer rate the ticks are counted in: exactly one declaration of TIMER_HZ in the kernel,
      `const TIMER_HZ: u32 = 1000;` in arch/x86_64/irq.rs (another rate changes the budget's
      seconds silently).
    Outside the guard (the auditor's survivors, accepted): a const generated by a macro, a
    function-local `use … as` alias, a rebinding of the start tick (`let t0 = t0 - …`) and a clamp
    inside request(); review, not this text check, covers them."""
    code = {rel: rust_code(text) for rel, text in files.items()}
    bad = []
    decls = [(rel, m) for rel, c in code.items()
             for m in re.finditer(r"\b(?:const|static)\s+(?:mut\s+)?LOAD_BUDGET_TICKS\b[^;]*;", c)]
    if len(decls) != 1:
        bad.append(f"{len(decls)} declarations of LOAD_BUDGET_TICKS: {[rel for rel, _ in decls]}")
    for rel, m in decls:
        v = re.fullmatch(r"const\s+LOAD_BUDGET_TICKS\s*:\s*u64\s*=\s*([0-9_]+)\s*;", m.group(0))
        if not v:
            bad.append(f"{rel}: `{m.group(0)}` is not `const LOAD_BUDGET_TICKS: u64 = <literal>;`")
        elif int(v.group(1).replace("_", "")) != LOAD_BUDGET_VALUE:
            bad.append(f"{rel}: LOAD_BUDGET_TICKS = {v.group(1)}, not {LOAD_BUDGET_VALUE}")
    defs = [rel for rel, c in code.items() for _ in re.finditer(r"\bfn\s+start_at_boot\b", c)]
    if defs != [LOAD_CALLEE]:
        bad.append(f"start_at_boot defined in {defs}, expected once in {LOAD_CALLEE}")
    uses = [(rel, m) for rel, c in code.items() for m in re.finditer(r"\bstart_at_boot\b", c)
            if not re.search(r"\bfn\s+$", c[:m.start()][-8:])]
    calls = [(rel, m) for rel, m in uses if re.match(r"start_at_boot\s*\(", code[rel][m.start():])]
    for rel, m in uses:
        if (rel, m) not in calls:
            bad.append(f"{rel}: start_at_boot named without a call ({code[rel][m.start():m.start() + 40].splitlines()[0]!r})")
    if len(calls) != 1:
        bad.append(f"{len(calls)} calls of start_at_boot: {[rel for rel, _ in calls]}")
    for rel, m in calls:
        arg = re.match(r"start_at_boot\s*\(\s*([^,()]*?)\s*,", code[rel][m.start():])
        if rel != LOAD_CALLER:
            bad.append(f"{rel}: start_at_boot called outside {LOAD_CALLER}")
        if not arg or arg.group(1) != "LOAD_BUDGET_TICKS":
            bad.append(f"{rel}: start_at_boot called with {arg.group(1) if arg else '?'!r}, not LOAD_BUDGET_TICKS")
    hz = [(rel, m) for rel, c in code.items()
          for m in re.finditer(r"\b(?:const|static)\s+(?:mut\s+)?TIMER_HZ\b[^;]*;", c)]
    if len(hz) != 1 or hz[0][0] != TIMER_FILE:
        bad.append(f"{len(hz)} declarations of TIMER_HZ: {[rel for rel, _ in hz]}, expected one in {TIMER_FILE}")
    for rel, m in hz:
        v = re.fullmatch(r"const\s+TIMER_HZ\s*:\s*u32\s*=\s*([0-9_]+)\s*;", m.group(0))
        if not v or int(v.group(1).replace("_", "")) != TIMER_HZ_VALUE:
            bad.append(f"{rel}: TIMER_HZ = {v.group(1) if v else m.group(0)}, not {TIMER_HZ_VALUE}")
    body = fn_body(code.get(LOAD_CALLEE, ""), "start_at_boot")
    if body is not None:
        n = len(re.findall(r"\btimeout_ticks\b", body))
        if n != 1 or not re.search(r"\bt0\s*\+\s*timeout_ticks\s*\)", body):
            bad.append(f"{LOAD_CALLEE}: start_at_boot uses timeout_ticks {n} time(s), not once as `t0 + timeout_ticks`")
    return bad


class LoadBudget(unittest.TestCase):
    GOOD_KMAIN = ("/// The interactive LOAD budget (boot.md).\n"
                  "#[cfg(all(target_arch = \"x86_64\", not(feature = \"ktest\")))]\n"
                  "pub const LOAD_BUDGET_TICKS: u64 = 10_000;\n"
                  "pub fn kernel_main() {\n"
                  "    // formerly start_at_boot(2000, ...)\n"
                  "    let (ok, line) = crate::services::start_at_boot(LOAD_BUDGET_TICKS, mode.manifest());\n"
                  "}\n")

    def tree(self, kmain=None, services=None, irq=None, **extra):
        files = {LOAD_CALLER: self.GOOD_KMAIN if kmain is None else kmain,
                 LOAD_CALLEE: (ROOT / LOAD_CALLEE).read_text(encoding="utf-8") if services is None else services,
                 TIMER_FILE: (ROOT / TIMER_FILE).read_text(encoding="utf-8") if irq is None else irq}
        files.update({f"kernel/src/{k}.rs": v for k, v in extra.items()})
        return files

    def test_the_interactive_load_wait_uses_the_named_budget(self):
        self.assertEqual(load_budget_violations(kernel_sources(ROOT)), [])

    def test_the_guard_accepts_the_named_budget_and_drops_comments_and_strings(self):
        self.assertEqual(load_budget_violations(self.tree()), [])
        self.assertEqual(rust_code('a /* b /* c */ d */ e // f\n"g\\"h" r#"i"# \'"\' j'), 'a   e \n"" "" \' \' j')

    def assertFlags(self, files, *fragments):
        bad = load_budget_violations(files)
        self.assertTrue(bad, "the guard accepted a decoy")
        for f in fragments:
            self.assertTrue(any(f in b for b in bad), f"{f!r} not in {bad}")

    def test_the_guard_sees_a_wrong_value_and_a_literal_call(self):
        g = self.GOOD_KMAIN
        self.assertFlags(self.tree(g.replace("10_000", "2000")), "LOAD_BUDGET_TICKS = 2000, not 10000")
        self.assertFlags(self.tree(g.replace("(LOAD_BUDGET_TICKS,", "(2000,")), "called with '2000'")
        self.assertFlags(self.tree(g.replace("pub const LOAD_BUDGET_TICKS: u64 = 10_000;\n", "")),
                         "0 declarations of LOAD_BUDGET_TICKS")

    def test_decoy_an_indented_shadowing_const(self):
        g = self.GOOD_KMAIN.replace("pub fn kernel_main() {\n", "pub fn kernel_main() {\n    const LOAD_BUDGET_TICKS: u64 = 2000;\n")
        self.assertFlags(self.tree(g), "2 declarations of LOAD_BUDGET_TICKS", "LOAD_BUDGET_TICKS = 2000")

    def test_decoy_a_second_declaration_under_another_cfg(self):
        g = self.GOOD_KMAIN + "#[cfg(feature = \"ktest\")]\npub const LOAD_BUDGET_TICKS: u64 = 2000;\n"
        self.assertFlags(self.tree(g), "2 declarations of LOAD_BUDGET_TICKS")
        self.assertFlags(self.tree(other="pub static LOAD_BUDGET_TICKS: u64 = 10_000;\n"), "2 declarations")

    def test_decoy_a_commented_or_quoted_call_beside_another_const(self):
        g = (self.GOOD_KMAIN.replace("(LOAD_BUDGET_TICKS,", "(OTHER,")
             + "const OTHER: u64 = 2000;\n// start_at_boot(LOAD_BUDGET_TICKS, m)\n"
             + "/* start_at_boot(LOAD_BUDGET_TICKS, m) */ const S: &str = \"start_at_boot(LOAD_BUDGET_TICKS, m)\";\n")
        self.assertFlags(self.tree(g), "called with 'OTHER', not LOAD_BUDGET_TICKS")

    def test_decoy_an_alias_or_a_function_pointer(self):
        alias = self.GOOD_KMAIN + "use crate::services::start_at_boot as sab;\nfn d() { sab(2000, m); }\n"
        self.assertFlags(self.tree(alias), "start_at_boot named without a call")
        ptr = self.GOOD_KMAIN + "fn d() { let f = crate::services::start_at_boot; f(2000, m); }\n"
        self.assertFlags(self.tree(ptr), "start_at_boot named without a call")
        second = self.tree(other="fn e() { crate::services::start_at_boot(2000, m); }\n")
        self.assertFlags(second, "2 calls of start_at_boot", "called outside kernel/src/kmain.rs")

    def test_decoy_another_timer_rate(self):
        # The budget is counted in ticks; its seconds follow TIMER_HZ (the auditor, WP-82).
        real = (ROOT / TIMER_FILE).read_text(encoding="utf-8")
        line = "pub const TIMER_HZ: u32 = 1000;"
        self.assertEqual(real.count(line), 1)
        self.assertFlags(self.tree(irq=real.replace(line, "pub const TIMER_HZ: u32 = 100;")), "TIMER_HZ = 100, not 1000")
        self.assertFlags(self.tree(other="pub const TIMER_HZ: u32 = 100;\n"), "2 declarations of TIMER_HZ")
        self.assertFlags(self.tree(irq=real.replace(line, "")), "0 declarations of TIMER_HZ")

    def test_decoy_a_clamp_inside_start_at_boot(self):
        real = (ROOT / LOAD_CALLEE).read_text(encoding="utf-8")
        anchor = "    let t0 = sched::ticks();\n"
        self.assertEqual(real.count(anchor), 1)
        clamp = real.replace(anchor, anchor + "    let timeout_ticks = timeout_ticks.min(2000);\n")
        self.assertFlags(self.tree(services=clamp), "uses timeout_ticks 3 time(s)")
        rebound = real.replace("t0 + timeout_ticks", "t0 + 2000")
        self.assertFlags(self.tree(services=rebound), "uses timeout_ticks 0 time(s)")
        twice = real.replace("pub fn start_at_boot(", "pub fn start_at_boot_x() {}\npub fn start_at_boot(") + "\nfn start_at_boot() {}\n"
        self.assertFlags(self.tree(services=twice), "start_at_boot defined in")

# PLAN-ANSWER §3.4 item 3: fw_cfg is host-controlled input, so the only kernel code that may
# reach it is the boot-mode decision (bootmode.rs), the test kernel's case selector (ktest.rs)
# and the driver itself (fwcfg.rs). A new caller would widen what the host can steer on a
# release boot; this guard makes that a reviewed change of the allowed set, not a silent one.
FWCFG_CALLERS = {"kernel/src/bootmode.rs", "kernel/src/ktest.rs", "kernel/src/arch/x86_64/fwcfg.rs"}
# Files that may name the module (declare or re-export it) without calling into it.
FWCFG_DECLARERS = {"kernel/src/arch/mod.rs", "kernel/src/arch/x86_64/mod.rs"}
FWCFG_FILE = "kernel/src/arch/x86_64/fwcfg.rs"


def fwcfg_violations(root):
    """Kernel sources that reach fw_cfg outside the allowed set: an exact identifier match
    (word boundaries, so `read_file_x` or `my_read_file` do not count) on every public entry of
    fwcfg.rs (read_file, hypervisor_present, any later one), on the module name `fwcfg`, and on
    the fw_cfg ports 0x510/0x511 (a second driver poking the ports directly)."""
    root = pathlib.Path(root)
    entries = re.findall(r"^pub fn (\w+)", (root / FWCFG_FILE).read_text(encoding="utf-8"), re.M)
    bad = []
    for p in sorted((root / "kernel" / "src").rglob("*.rs")):
        rel = p.relative_to(root).as_posix()
        if rel in FWCFG_CALLERS:
            continue
        text = p.read_text(encoding="utf-8")
        for ident in entries:
            if re.search(rf"\b{ident}\b", text):
                bad.append(f"{rel}: {ident}")
        if rel not in FWCFG_DECLARERS and re.search(r"\bfwcfg\b", text):
            bad.append(f"{rel}: fwcfg")
        if re.search(r"\b0x51[01]\b", text, re.I):
            bad.append(f"{rel}: fw_cfg port")
    return entries, bad


class FwCfgCallers(unittest.TestCase):
    def test_fw_cfg_is_reached_only_from_the_boot_mode_and_the_test_kernel(self):
        entries, bad = fwcfg_violations(ROOT)
        self.assertIn("read_file", entries)
        self.assertEqual(bad, [])

    def test_the_guard_sees_a_new_caller(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            for rel in FWCFG_CALLERS | FWCFG_DECLARERS:
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / rel, d / rel)
            (d / "kernel/src/net.rs").write_text("use crate::arch::fwcfg::read_file as rf;\nfn x() { rf(\"a\", &mut []); }\n")
            (d / "kernel/src/disk.rs").write_text("fn y() { unsafe { outw(0x510, 0) } }\n")
            (d / "kernel/src/vfs.rs").write_text("fn read_file_at() {}\n")
            self.assertEqual(fwcfg_violations(d)[1], ["kernel/src/disk.rs: fw_cfg port",
                                                      "kernel/src/net.rs: read_file", "kernel/src/net.rs: fwcfg"])


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
        # The branch holds the whole committed evidence tree (verify.yml: `git add -f evidence/`):
        # the directory above, without ci identity, is already under the root's evidence/ and is
        # skipped; this run's own directory carries the runner's identity and is imported (WP-81).
        self.new_dir = work / "evidence" / "20260102T000000Z-deadbeef-001"
        self.new_dir.mkdir(parents=True)
        (self.new_dir / "verdict.json").write_text(json.dumps({"test_id": "TST-X", "verdict": "PASS"}))
        (self.new_dir / "run.json").write_text(json.dumps({"run_id": self.new_dir.name, "worker": "verification-runner",
                                                           "ci": {"run_id": "42", "run_attempt": 1, "sha": "cafe"}}))
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
        shutil.copytree(self.run_dir, self.root / "evidence" / self.run_dir.name)
        (self.root / "base.txt").write_text("the committed base")
        self.git(self.root, "add", "base.txt", "evidence")
        self.git(self.root, "commit", "-q", "-m", "base")
        head = self.git(self.root, "rev-parse", "HEAD").stdout.strip()
        (self.root / "staged.txt").write_text("the user's work")
        self.git(self.root, "add", "staged.txt")
        # The checked import (ADR-0026) asks gh for the run: a fake gh on PATH answers success
        # for a verify run whose head is the root's HEAD.
        bindir = base / "bin"; bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text("#!/bin/sh\ncat <<'JSON'\n" + json.dumps({"status": "completed", "conclusion": "success", "headSha": head,
                                                                   "event": "pull_request", "workflowName": "verify", "attempt": 1}) + "\nJSON\n")
        gh.chmod(0o755)
        self.env["PATH"] = f"{bindir}:{self.env['PATH']}"

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
        self.assertTrue((self.root / "evidence" / self.new_dir.name / "import.json").exists())
        # the committed directory without ci identity neither refused the import nor got a receipt
        self.assertFalse((self.root / "evidence" / self.run_dir.name / "import.json").exists())
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
    def test_mutants_runs_the_gates_in_order_and_publishes_every_report(self):
        # WP-38 phase 1 (2026-10-28): the M5 step was added but its report was left out of the
        # evidence branch's `git add`, and no test held the gate order; the records check
        # before the runs was not strict.
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        names = [str(s.get("name", "")) for s in steps]
        gates = [n for n in names if n.startswith("Mutation run, ")]
        self.assertEqual([g.split(",")[1].strip()[:2] for g in gates], ["M2", "M3", "M4", "M5"],
                         "the gates run in order M2, M3, M4, M5")
        runs = [s["run"] for s in steps if str(s.get("name", "")).startswith("Mutation run, ")]
        self.assertEqual(runs, [f"python3 tools/project.py test --target host --suite {x}" for x in ("M2", "M3-GATE", "M4-GATE", "M5-GATE")])
        for s in steps[1:]:
            if str(s.get("name", "")).startswith("Mutation run, ") and not s["name"].startswith("Mutation run, M2"):
                self.assertEqual(s.get("if"), "always()", f"{s['name']}: a failed gate must not skip the next")
        validate = [s for s in steps if str(s.get("name", "")).startswith("validate-records")]
        self.assertEqual(len(validate), 1)
        self.assertIn("--strict", validate[0]["run"], "the records check before the runs is strict")
        publish = next(s for s in steps if str(s.get("name", "")).startswith("Publish evidence"))
        run = publish["run"]
        self.assertIn("git add -f evidence/", run)
        # Run 42481065666: one `git add` of every report failed when M2 had none, and the M5
        # report was lost with it; each report is added on its own, if it exists.
        self.assertNotRegex(run, r"git add -f evidence/ build/", "one missing report must not drop the others")
        loop = next(l for l in run.splitlines() if l.strip().startswith("for r in "))
        self.assertIn('if [ -f "$r" ]; then git add -f "$r"; fi', run)
        for rep in ("build/mutants-report.json", "build/mutants-m3-report.json", "build/mutants-m4-report.json", "build/mutants-m5-report.json"):
            self.assertIn(rep, loop, f"{rep} is not published on the evidence branch")

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
