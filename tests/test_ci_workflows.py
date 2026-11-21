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

import fnmatch
import json
import re
import os
import shlex
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


# WP-152: verify runs the M6 mutation gate in SHARDS jobs `shard-1` … `shard-<SHARDS>` (job `shard-k`
# runs shard k), each TST-M6-MUTANTS's own command with `--shard k/SHARDS` (WP-98's hand-off) and
# uploading its report alone as `mutants-m6-shard-<k>`; job `g` (slot g) needs them all, downloads
# the reports and runs the gate's unchanged suite with NAWAH_GATE_SHARDS=SHARDS on that step alone,
# which merges them into the gate's one verdict.
SHARDS = 12  # WP-153: 6 -> 12, the longest shard 1242 -> 655 s of run 44229918866's mutant seconds
SHARD_JOB = re.compile(r"shard-([1-9][0-9]*)")
GATE_SHARDS = "NAWAH_GATE_SHARDS"

# WP-153 (run 44229918866): `evidence/*-a/` matched every committed -a directory of older runs too,
# so job a's upload (188 s) and the merge's download (132 s) grew with every run. A run directory
# is named <stamp>-<HEAD's first 8 hex>-<nnn>-<slot> (project.py new_run_dir, source_identity), so a
# slot uploads only the directories of the checked-out commit, whose first 8 characters a step
# `rev` writes to its output just before the upload.
REV_RUN = 'echo "sha8=$(git rev-parse HEAD | cut -c1-8)" >> "$GITHUB_OUTPUT"'
RUN_DIRS = "evidence/*-${{{{ steps.rev.outputs.sha8 }}}}-*-{slot}/"


def upload_paths(step):
    """An upload step's path lines (one per line: an expression such as
    `${{ steps.rev.outputs.sha8 }}` holds spaces)."""
    return [x.strip() for x in str(step.get("with", {}).get("path", "")).splitlines() if x.strip()]


def artifact_root(paths):
    """The directory, relative to the workspace ("" for the workspace itself), that the pinned
    upload-artifact (ea165f8d, src/shared/search.ts:126-157) makes the root of an artifact of these
    path lines: each line's search path is its literal prefix before the first segment holding `*`,
    `?` or `[` (@actions/glob); a search path equal to or under another one is dropped; with more
    than one left the root is their lowest common ancestor, with one it is that path itself, but
    the parent of a single plain file (search.ts:144-151). The WP-153 review's blocker: job b's
    one line `evidence/*-…-b/` made `evidence` the root, so its run directories arrived without
    the `evidence/` level the merge job reads."""
    search, plain = [], []
    for line in paths:
        parts = [s for s in line.rstrip("/").split("/") if s not in ("", ".")]
        lit = []
        for s in parts:
            if any(c in s for c in "*?["):
                break
            lit.append(s)
        search.append(tuple(lit))
        plain.append(len(lit) == len(parts) and not line.endswith("/"))
    kept = []
    for s in sorted(set(search), key=len):
        if not any(s[:len(k)] == k for k in kept):
            kept.append(s)
    if len(kept) > 1:
        common = []
        for parts in zip(*kept):
            if len(set(parts)) != 1:
                break
            common.append(parts[0])
        return "/".join(common)
    if len(paths) == 1 and plain[0]:
        return "/".join(kept[0][:-1])
    return "/".join(kept[0])


def gate_case():
    return next(c for c in project.HOST_SUITES["M6-GATE"] if c["id"] == "TST-M6-MUTANTS")


# A Toolchain step's retry(): two or more tries of a command, each under `timeout`, a pause after a
# failed one. Its per-try limit is its own (`timeout 300 "$@"`) or the first argument of each call
# (`t=$1; shift; … timeout "$t" "$@"`, then `retry 100 cmd …`).
RETRY_DEF = re.compile(r'retry\(\) \{ (t=\$1; shift; )?for i in ([\d ]+); do (?:s=\$SECONDS; )?timeout (\d+|"\$t") [^}]*sleep (\d+)')


def toolchain_steps():
    """(workflow, job, step) of every Toolchain step of verify.yml and mutants.yml."""
    for name in ("verify.yml", "mutants.yml"):
        for job, body in load(name)["jobs"].items():
            for s in body["steps"]:
                if str(s.get("name", "")).startswith("Toolchain"):
                    yield name, job, s


def retry_plan(run):
    """(attempts, pause, calls) of a Toolchain step's run text, calls as (line index, per-try limit
    or None when the call names none, command), or None when retry() is not in RETRY_DEF's form."""
    m = RETRY_DEF.search(run)
    if not m or (m.group(3) == '"$t"') != bool(m.group(1)):
        return None
    fixed = None if m.group(3) == '"$t"' else int(m.group(3))
    calls = []
    for i, line in enumerate(l.strip() for l in run.splitlines()):
        c = re.fullmatch(r"(?:if ! )?retry (.+)", line)
        if not c:
            continue
        n = re.fullmatch(r"(\d+) (.+)", c.group(1)) if fixed is None else None
        calls.append((i, fixed if fixed is not None else (int(n.group(1)) if n else None), n.group(2) if n else c.group(1)))
    return len(m.group(2).split()), int(m.group(4)), calls


def mirror_rewrite(run):
    """The fallback's mirror rewrite of a Toolchain step as (sed options and expression, the files
    it edits): its one `sed` line, `sudo` and the trailing redirection or `|| true` dropped."""
    lines = [l.strip() for l in run.splitlines() if re.match(r"(sudo )?sed ", l.strip())]
    if len(lines) != 1:
        return None
    argv = []
    for tok in shlex.split(lines[0]):
        if tok in ("||", "&&", ";") or tok.startswith("2>"):
            break
        argv.append(tok)
    argv = argv[1:] if argv[0] == "sudo" else argv
    files = [t for t in argv[1:] if t.startswith("/")]
    return argv[1:len(argv) - len(files)], files


def shard_command(k, n):
    """Shard k of n's step: TST-M6-MUTANTS's own command with `--shard k/n`, never a copy of it."""
    return " ".join(gate_case()["command"] + ["--shard", f"{k}/{n}"])


def shard_report(k, n):
    """Where shard k of n writes its report (tests/mutants.py shard_report on the case's --report)."""
    sys.path.insert(0, str(ROOT / "tests"))
    import mutants  # noqa: E402
    cmd = gate_case()["command"]
    return mutants.shard_report(cmd[cmd.index("--report") + 1], k, n)


def shard_dir():
    return pathlib.PurePosixPath(shard_report(1, SHARDS)).parent.as_posix()


def shard_jobs(jobs):
    return {name: job for name, job in jobs.items() if SHARD_JOB.fullmatch(name)}


def shard_problems(name, job, n):
    """What keeps job `name` from being shard k of n of the M6 gate (WP-152), the narrow and named
    exception to the slot rule (MergeJob.slot_problems): a shard writes no evidence and no verdict
    (no NAWAH_RUN_SLOT anywhere in the job, no `project.py test`, a scratch root on every other
    project.py step), runs TST-M6-MUTANTS's own command with `--shard k/n` once, in a step capped
    and continue-on-error (its exit is its own mutants' line, not the gate's verdict: job g fails
    closed on a shard that did not finish), needs nothing, may not write, and uploads exactly one
    artifact, `mutants-m6-shard-<k>`, holding its report alone (always, continue-on-error)."""
    bad = []
    k = int(SHARD_JOB.fullmatch(name).group(1))
    if not 1 <= k <= n:
        bad.append(f"{name}: shard {k} of {n}")
    if "NAWAH_RUN_SLOT" in json.dumps(job):
        bad.append(f"{name}: a shard has no run slot")
    if job.get("needs") or job.get("if") is not None:
        bad.append(f"{name}: a shard needs nothing and always runs")
    if "write" in str(job.get("permissions", {})):
        bad.append(f"{name}: a shard may not write")
    steps = job["steps"]
    runs = [(s, l.strip()) for s in steps for l in str(s.get("run", "")).splitlines()]
    if [l for _, l in runs if "project.py test" in l]:
        bad.append(f"{name}: a shard writes no verdict (project.py test)")
    gate = [(s, l) for s, l in runs if "tests/mutants.py" in l]
    if [l for _, l in gate] != [shard_command(k, n)]:
        bad.append(f"{name}: {[l for _, l in gate]}, not [{shard_command(k, n)!r}]")
    elif gate[0][0].get("continue-on-error") is not True or "timeout-minutes" not in gate[0][0]:
        bad.append(f"{name}: the shard step is not capped and continue-on-error")
    for s, l in runs:
        if "project.py " in l and not str((s.get("env") or {}).get("NAWAH_SCRATCH_EVIDENCE", "")).startswith("${{ runner.temp }}/"):
            bad.append(f"{name}: {l!r} writes evidence outside a scratch root")
    ups = [s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    if len(ups) != 1:
        bad.append(f"{name}: {len(ups)} uploads, not one")
    else:
        up = ups[0]
        if up.get("with", {}).get("name") != f"mutants-m6-shard-{k}":
            bad.append(f"{name}: uploads {up.get('with', {}).get('name')!r}, not 'mutants-m6-shard-{k}'")
        if str(up.get("with", {}).get("path", "")).split() != [shard_report(k, n)]:
            bad.append(f"{name}: uploads {str(up.get('with', {}).get('path', '')).split()}, not its report alone")
        if "always()" not in str(up.get("if", "")) or up.get("continue-on-error") is not True:
            bad.append(f"{name}: the upload is not always() with continue-on-error")
    return bad


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
                # All attempts of a call end inside the step's limit, and each failed attempt
                # leaves an annotation (the logs may be unreadable, the check-run annotations are
                # not). How long one attempt may be is the budget case's (FallbackMirror).
                plan = retry_plan(run)
                self.assertIsNotNone(plan, f"{name}: {job}: no retry() with a per-attempt timeout in the expected form")
                attempts, pause, calls = plan
                self.assertGreaterEqual(attempts, 2, f"{name}: {job}: no second attempt")
                for _, limit, cmd in calls:
                    self.assertIsNotNone(limit, f"{name}: {job}: a call names no per-attempt limit: {cmd}")
                    self.assertLessEqual(attempts * limit + (attempts - 1) * pause, step["timeout-minutes"] * 60,
                                         f"{name}: {job}: the attempts outlast the step: {cmd}")
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


class FallbackMirror(unittest.TestCase):
    """WP-152's follow-up (verify run 44218469147 on 172ba7707, both attempts): on the EC2 runners
    the runner's mirror is a regional host, http://us-east-2.ec2.archive.ubuntu.com/ubuntu/
    (priority 1 in /etc/apt/apt-mirrors.txt, the check-run annotations of shard-6), and two 300 s
    fetches from it ended rc=124 with 80 and 88 packages; the fallback's rewrite matched the Azure
    mirror alone, changed nothing, and the step hit its 15-min cap in five shard jobs. Every
    Toolchain step's rewrite, applied for real with sed to copies of both mirror files, turns every
    regional *.archive.ubuntu.com host into archive.ubuntu.com and leaves every other host alone;
    and the runner's mirror is given at most half of the step's cap in the worst case, so the
    fallback has the other half."""

    MIRRORS = ("http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\tpriority:1\n"
               "http://azure.archive.ubuntu.com/ubuntu/\tpriority:2\n"
               "http://eu-west-1.ec2.archive.ubuntu.com/ubuntu/\tpriority:3\n"
               "http://de.archive.ubuntu.com/ubuntu/\tpriority:4\n"
               "https://archive.ubuntu.com/ubuntu/\tpriority:5\n"
               "https://security.ubuntu.com/ubuntu/\tpriority:6\n"
               "https://packages.microsoft.com/ubuntu/24.04/prod\tpriority:7\n")
    SOURCES = ("## See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade.\n"
               "Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\nSuites: noble noble-updates noble-backports\n"
               "Components: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
               "Types: deb\nURIs: http://us-east-2.ec2.archive.ubuntu.com/ubuntu/ http://azure.archive.ubuntu.com/ubuntu/\n"
               "Suites: noble\nComponents: main\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
               "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble-updates\nComponents: main\n\n"
               "Types: deb\nURIs: http://security.ubuntu.com/ubuntu\nSuites: noble-security\nComponents: main\n\n"
               "Types: deb\nURIs: https://packages.microsoft.com/ubuntu/24.04/prod\nSuites: noble\nComponents: main\n")
    FILES = ("/etc/apt/apt-mirrors.txt", "/etc/apt/sources.list.d/ubuntu.sources")
    REGIONAL = re.compile(r"://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.archive\.ubuntu\.com/")

    def test_the_fallback_rewrites_every_regional_mirror_and_nothing_else(self):
        steps = list(toolchain_steps())
        self.assertGreaterEqual(len(steps), 4 + SHARDS + 1, "a, b, the shards, g, merge and mutants.yml's job")
        for name, job, step in steps:
            where = f"{name}: {job}"
            rewrite = mirror_rewrite(step["run"])
            self.assertIsNotNone(rewrite, f"{where}: not one sed line in the fallback")
            args, files = rewrite
            self.assertEqual(files, list(self.FILES), f"{where}: the rewrite does not edit both mirror files")
            self.assertIn("-i", args, f"{where}: the rewrite does not edit in place")
            with tempfile.TemporaryDirectory() as tmp:
                copies = []
                for f, text in zip(self.FILES, (self.MIRRORS, self.SOURCES)):
                    copy = pathlib.Path(tmp) / pathlib.PurePosixPath(f).name
                    copy.write_text(text, encoding="utf-8")
                    copies.append(copy)
                r = subprocess.run(["sed", *args, *map(str, copies)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, f"{where}: sed {args}: {r.stderr}")
                for copy, text in zip(copies, (self.MIRRORS, self.SOURCES)):
                    got = copy.read_text(encoding="utf-8")
                    self.assertNotRegex(got, self.REGIONAL, f"{where}: a regional host is left in {copy.name}")
                    # Each regional host becomes archive.ubuntu.com, scheme and path kept; every
                    # other line (archive.ubuntu.com itself, security.ubuntu.com,
                    # packages.microsoft.com, the comment, mirror+file:) stays byte for byte.
                    self.assertEqual(got, self.REGIONAL.sub("://archive.ubuntu.com/", text), f"{where}: {copy.name}")

    def test_the_runner_mirror_leaves_the_fallback_half_the_step(self):
        for name, job, step in toolchain_steps():
            where = f"{name}: {job}"
            run = step["run"]
            plan = retry_plan(run)
            self.assertIsNotNone(plan, f"{where}: retry() not in the expected form")
            attempts, pause, calls = plan
            lines = [l.strip() for l in run.splitlines()]
            at = [i for i, l in enumerate(lines) if re.match(r"(sudo )?sed ", l)]
            self.assertEqual(len(at), 1, f"{where}: not one mirror rewrite")
            before = [c for c in calls if c[0] < at[0]]
            self.assertTrue(before, f"{where}: the runner's mirror is not tried first")
            # Worst case before the fallback starts: every try of the runner's mirror (the update
            # and the fetch) runs to its limit and is followed by its pause.
            worst = sum(attempts * ((limit or 0) + pause) for _, limit, _ in before)
            self.assertLessEqual(worst, step["timeout-minutes"] * 60 / 2,
                                 f"{where}: the runner's mirror may take {worst} s of the step's {step['timeout-minutes'] * 60}")
            for i, limit, cmd in calls:
                self.assertIsNotNone(limit, f"{where}: a call names no per-attempt limit: {cmd}")
                if i < at[0]:
                    # A try of the runner's mirror may be short (what it fetched stays in the cache
                    # for the next try and the fallback), but longer than apt's own stall timeout,
                    # so apt drops a stalled connection and retries inside one try.
                    stall = re.search(r"Acquire::http::Timeout=(\d+)", cmd)
                    self.assertTrue(stall and limit > int(stall.group(1)), f"{where}: {limit} s: {cmd}")
                else:
                    # Run 40362082749's healthy Toolchain step took 5 minutes; in run 40367178852 a
                    # 240 s attempt limit killed one download three times and failed the job: the
                    # fallback, the installation and rustup keep tries that outlast a slow download.
                    self.assertGreaterEqual(limit, 300, f"{where}: an attempt dies before a slow download ends: {cmd}")


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
        # DEC-029 option A (WP-96): the open stage's gate runs in verify, in its own job, so its
        # evidence is of the same run as every other verdict; the older gates stay in mutants.yml.
        in_verify = {"M6-GATE"}
        expected = {k for k in project.HOST_SUITES if (not k.endswith("-GATE") or k in in_verify) and k not in excluded}
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
        """({job: slot}, problems) of the test jobs' slots and evidence uploads. A job named
        `shard-<k>` is a shard of the M6 gate (WP-152): it has no slot and is held to
        shard_problems instead, never merely skipped."""
        slots, bad = {}, []
        n = len(shard_jobs(jobs))
        for name, job in jobs.items():
            if name == "merge":
                continue
            if SHARD_JOB.fullmatch(name):
                bad += shard_problems(name, job, n)
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
            paths = upload_paths(up)
            # Exactly the slot's run directories of this run under evidence/, nothing wider (the
            # auditor, 83a; WP-153: not the older runs' committed directories of the slot either).
            ev = [x for x in paths if x.startswith("evidence")]
            if ev != [RUN_DIRS.format(slot=slot)]:
                bad.append(f"{name}: evidence paths {ev}, not exactly [{RUN_DIRS.format(slot=slot)!r}]")
            revs = [i for i, s in enumerate(job["steps"]) if s.get("id") == "rev"]
            if len(revs) != 1 or revs[0] > job["steps"].index(up) or job["steps"][revs[0]].get("run") != REV_RUN \
                    or "always()" not in str(job["steps"][revs[0]].get("if", "")):
                bad.append(f"{name}: no always() step `rev` running {REV_RUN!r} before the upload")
            if "always()" not in str(up.get("if", "")) or up.get("continue-on-error") is not True:
                bad.append(f"{name}: the upload is not always() with continue-on-error")
        if not slots:
            bad.append("no test job")
        return slots, bad

    def test_every_test_job_writes_and_uploads_its_own_slot(self):
        self.assertEqual(self.slot_problems(self.jobs())[1], [])

    def test_an_upload_beyond_the_slots_run_directories_is_refused(self):
        # The auditor (83a): `evidence/*` beside `evidence/*-a/` uploads the whole tree again.
        for extra in ("evidence/*", "evidence", "evidence/**", RUN_DIRS.format(slot="b"), "evidence/*-a/"):
            jobs = load("verify.yml")["jobs"]
            up = next(s for s in jobs["a"]["steps"] if s.get("with", {}).get("name") == "evidence-a")
            up["with"]["path"] = up["with"]["path"] + extra + "\n"
            self.assertTrue(self.slot_problems(jobs)[1], f"{extra!r} accepted")
        # Job a's upload back to every directory of its slot, or its step `rev` changed, dropped or
        # run only when the job succeeds (the upload runs always).
        for tamper in (lambda j: [s["with"].update(path="evidence/*-a/\n") for s in j["steps"] if s.get("with", {}).get("name") == "evidence-a"],
                       lambda j: [s.update(run=REV_RUN.replace("1-8", "1-7")) for s in j["steps"] if s.get("id") == "rev"],
                       lambda j: [j["steps"].remove(s) for s in list(j["steps"]) if s.get("id") == "rev"],
                       lambda j: [s.pop("if") for s in j["steps"] if s.get("id") == "rev"]):
            jobs = load("verify.yml")["jobs"]
            tamper(jobs["a"])
            self.assertTrue(self.slot_problems(jobs)[1])

    def test_the_rev_step_names_this_runs_directories_and_no_committed_one(self):
        # The step run for real (bash -e, as GitHub runs a step without `shell:`) prints the first
        # 8 characters of the revision project.py names its run directories with; the pattern then
        # takes a directory of this run in its slot alone, and none of the directories committed
        # under evidence/ (git ls-tree HEAD, checked out or not).
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            out.write_text("")
            r = subprocess.run(["bash", "-e", "-c", REV_RUN], cwd=ROOT, env=dict(os.environ, GITHUB_OUTPUT=str(out)),
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            sha8 = dict(l.split("=", 1) for l in out.read_text().splitlines())["sha8"]
        self.assertEqual(sha8, project.source_identity()[0][:8])
        other = "0" * 8 if sha8 != "0" * 8 else "1" * 8
        committed = subprocess.run(["git", "ls-tree", "--name-only", "HEAD", "evidence/"], cwd=ROOT,
                                   capture_output=True, text=True).stdout.split()
        for slot in sorted(self.slot_problems(self.jobs())[0].values()):
            pattern = RUN_DIRS.format(slot=slot).replace("${{ steps.rev.outputs.sha8 }}", sha8)
            self.assertTrue(fnmatch.fnmatchcase(f"evidence/20261118T035023Z-{sha8}-002-{slot}/", pattern), pattern)
            for name in (f"20261118T035023Z-{other}-002-{slot}", f"20261118T035023Z-{sha8}-002-z"):
                self.assertFalse(fnmatch.fnmatchcase(f"evidence/{name}/", pattern), name)
            self.assertEqual([c for c in committed if fnmatch.fnmatchcase(c.rstrip("/") + "/", pattern)], [], pattern)

    def test_a_shard_job_is_exempt_from_the_slot_only_in_its_narrow_shape(self):
        # WP-152 (the assurance challenge of WP-98): an exception wider than a shard's exact shape
        # (say, every job named shard-*) would reopen 83a's hole: evidence uploaded beside a slot.
        self.assertEqual(self.slot_problems(self.jobs())[1], [])
        up = lambda job: next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
        step = lambda job: next(s for s in job["steps"] if "tests/mutants.py" in str(s.get("run", "")))

        def slot_env(j):
            j.setdefault("env", {})["NAWAH_RUN_SLOT"] = "s"

        def slot_in_step(j):
            step(j).setdefault("env", {})["NAWAH_RUN_SLOT"] = "s"

        def evidence_beside(j):
            up(j)["with"]["path"] = up(j)["with"]["path"] + "\nevidence/*\n"

        def evidence_name(j):
            up(j)["with"]["name"] = "evidence-s"

        def a_verdict(j):
            j["steps"].insert(-1, {"run": "python3 tools/project.py test --target host --suite M6-GATE"})

        def baseline_into_evidence(j):
            next(s for s in j["steps"] if "project.py build" in str(s.get("run", ""))).pop("env", None)

        def a_second_upload(j):
            j["steps"].append(dict(up(j)))

        def writes(j):
            j["permissions"] = {"contents": "write"}

        def waits(j):
            j["needs"] = ["a"]

        def fails_the_run(j):
            step(j).pop("continue-on-error", None)

        def another_shard(j):
            step(j)["run"] = step(j)["run"].replace("--shard 1/", "--shard 2/")

        for tamper in (slot_env, slot_in_step, evidence_beside, evidence_name, a_verdict, baseline_into_evidence,
                       a_second_upload, writes, waits, fails_the_run, another_shard):
            jobs = self.jobs()
            tamper(jobs["shard-1"])
            self.assertTrue(self.slot_problems(jobs)[1], f"{tamper.__name__} accepted")

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
        # Each slot's artifact holds the workspace files under its root, as upload-artifact lays
        # them out (artifact_root, the WP-153 review), not a layout assumed here.
        roots = self.slot_roots()
        for slot, parts in layout.items():
            if parts is None:
                continue
            art = d / "incoming" / f"evidence-{slot}"
            art.mkdir(parents=True)
            root = pathlib.PurePosixPath(roots.get(slot, "")).parts

            def put(rel, text):
                rel = pathlib.PurePosixPath(rel).parts
                if rel[:len(root)] != root:
                    return  # outside the root: upload-artifact does not upload it
                dst = art.joinpath(*rel[len(root):])
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(text)
            if parts == "empty":
                put("evidence/README", "")
            if parts != "empty" and "run" in parts:
                put(f"evidence/20261110T000000Z-abcdef12-001-{slot}/verdict.json", "{}")
            if parts != "empty" and "build" in parts:
                put("build/pc-qemu/build-id.txt", slot)
        (d / "step.sh").write_text(self.adopt_step()["run"] if script is None else script)
        # GitHub's default for a run step without `shell:` on Linux: bash -e {0}.
        r = subprocess.run(["bash", "-e", str(d / "step.sh")], cwd=d, capture_output=True, text=True)
        args = json.loads((d / "adopt-args").read_text()) if (d / "adopt-args").exists() else None
        return r.returncode, r.stdout + r.stderr, args, d

    def slot_roots(self):
        """{slot: its artifact's root} of every `evidence-<slot>` upload of verify.yml."""
        jobs = self.jobs()
        roots = {}
        for name, slot in self.slot_problems(jobs)[0].items():
            up = next(s for s in jobs[name]["steps"] if s.get("with", {}).get("name") == f"evidence-{slot}")
            roots[slot] = artifact_root(upload_paths(up))
        return roots

    def test_every_slot_artifact_keeps_the_workspace_layout(self):
        # The WP-153 review's blocker: an upload whose lines share one search path is rooted
        # there, and the merge reads incoming/evidence-<slot>/evidence/<run>/ alone.
        self.assertEqual({s: r for s, r in self.slot_roots().items() if r != ""}, {}, "a slot's artifact is not rooted at the workspace")
        # The rule itself on its own cases.
        self.assertEqual(artifact_root(["evidence/*-x-*-b/"]), "evidence")
        self.assertEqual(artifact_root(["evidence/*-x-*-a/", "build/pc-qemu/build-id.txt", "build/hygiene.log"]), "")
        self.assertEqual(artifact_root(["build/mutants-m6-report.shards/shard-1-of-12.json"]), "build/mutants-m6-report.shards")
        self.assertEqual(artifact_root(["build/a/", "build/a/x/*.json"]), "build/a")
        self.assertEqual(artifact_root(["build/a/*", "build/b/?.log"]), "build")
        self.assertEqual(artifact_root(["evidence/[0-9]*/"]), "evidence")

    def test_a_build_file_two_slots_carry_is_the_same_build(self):
        # The merge's build-file copy loop copies each slot's build/ over the last one, in its
        # order: a slot other than a carrying a file a carries must make it the way a does, in
        # the same checkout (build-id.txt is HEAD's first 12 hex, project.py cmd_build).
        jobs = self.jobs()
        a_files = [x for x in upload_paths(next(s for s in jobs["a"]["steps"] if s.get("with", {}).get("name") == "evidence-a"))
                   if x.startswith("build/")]
        builds = lambda job: [l.strip() for s in job["steps"] for l in str(s.get("run", "")).splitlines()
                              if l.strip() == "python3 tools/project.py build --target pc-qemu"]
        for name, slot in self.slot_problems(jobs)[0].items():
            if name == "a":
                continue
            up = next(s for s in jobs[name]["steps"] if s.get("with", {}).get("name") == f"evidence-{slot}")
            for f in (x for x in upload_paths(up) if x in a_files):
                self.assertEqual(jobs[name]["steps"][0], jobs["a"]["steps"][0], f"{name}: {f} from another checkout")
                self.assertTrue(builds(jobs[name]) and builds(jobs["a"]), f"{name}: {f} not made by the same build")

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

class TestJobs(unittest.TestCase):
    """WP-153 (run 44229918866: job a 33.5 min, of which the M5 guest suite 635 s, then merge, made
    the run's critical path 39 min): the M5 guest suite runs in a job `b` of its own (slot b) beside
    job a, so the run ends when the longer of a, b and the shards' g does, plus merge. Job b has
    the test job's lab (the same checkout and Toolchain step), needs nothing and always runs, builds
    the images into a scratch root (TST-M1-BUILD stays job a's: two slots carrying one test are
    refused by adopt-native, M296) and runs the M5 guest suite and nothing else; job a no longer
    runs it. Every guest suite runs in exactly one job, and outside job a every build or boot of
    pc-qemu writes to a scratch root."""

    def jobs(self):
        return load("verify.yml")["jobs"]

    @staticmethod
    def suite_lines(job):
        return [l.strip() for s in job["steps"] for l in str(s.get("run", "")).splitlines() if "project.py test " in l]

    def test_job_b_runs_the_m5_guest_suite_alone_with_the_test_jobs_lab(self):
        jobs = self.jobs()
        self.assertIn("b", jobs, "verify has no job b")
        a, b = jobs["a"], jobs["b"]
        self.assertEqual(b.get("env", {}).get("NAWAH_RUN_SLOT"), "b")
        self.assertNotIn("needs", b, "b runs beside a, not after it")
        self.assertNotIn("if", b)
        self.assertNotIn("write", str(b.get("permissions", {})))
        self.assertEqual(b["steps"][0], a["steps"][0], "b's checkout is not the test job's")
        tool = lambda job: next(s for s in job["steps"] if str(s.get("name", "")).startswith("Toolchain"))
        self.assertEqual(tool(b)["run"], tool(a)["run"], "b's lab is not the test job's")
        self.assertEqual(self.suite_lines(b), ["python3 tools/project.py test --target pc-qemu --suite M5"])
        self.assertNotIn("python3 tools/project.py test --target pc-qemu --suite M5", self.suite_lines(a))
        runs = [str(s.get("run", "")) for s in b["steps"]]
        build = [i for i, r in enumerate(runs) if "project.py build --target pc-qemu" in r]
        suite = [i for i, r in enumerate(runs) if "--suite M5" in r]
        self.assertEqual(len(build), 1, "b builds the images once")
        self.assertLess(build[0], suite[0], "b builds before the suite")

    def test_every_guest_suite_runs_in_one_job(self):
        seen = {}
        for name, job in self.jobs().items():
            for line in self.suite_lines(job):
                m = re.search(r"--target pc-qemu --suite (\S+)", line)
                if m:
                    seen.setdefault(m.group(1), []).append(name)
        self.assertTrue(seen)
        self.assertEqual({s: n for s, n in seen.items() if len(n) != 1}, {}, "a guest suite runs in more than one job")

    def test_only_job_a_builds_or_boots_into_the_evidence(self):
        # TST-M1-BUILD and TST-M1-BOOT are job a's; a second job writing them leaves two new runs
        # of one test, which adopt-native refuses and the merge fails on (M296).
        for name, job in self.jobs().items():
            if name == "a":
                continue
            for s in job["steps"]:
                for line in str(s.get("run", "")).splitlines():
                    if re.search(r"project\.py (build|boot) --target pc-qemu\b", line):
                        scratch = str((s.get("env") or {}).get("NAWAH_SCRATCH_EVIDENCE", ""))
                        self.assertTrue(scratch.startswith("${{ runner.temp }}/"), f"{name}: {line.strip()} writes evidence")


class MutationJob(unittest.TestCase):
    """WP-96 (the owner's DEC-029, option A) and WP-152: the M6 mutation gate runs in every verify
    run beside the test job, so TST-M6-MUTANTS's evidence is of the same run as every other
    verdict and a stale gate verdict stays a strict error (no stale_policy on it). Since WP-152 it
    runs in SHARDS shard jobs `shard-1` … `shard-6` and one merge-gate job `g`. Each shard job has
    the test job's lab (the same checkout and Toolchain step), builds and boots the unmutated
    kernel first into a scratch root as mutants.yml does, runs TST-M6-MUTANTS's own command with
    `--shard k/6` (k from its name, so 1..6 each once) and uploads that shard's report alone; it
    writes no evidence and no verdict (shard_problems). Job g (slot g) needs every shard job and
    runs unless the run is cancelled, downloads this run's shard reports into the report's
    `.shards/` directory, and runs the gate's unchanged suite with NAWAH_GATE_SHARDS=6 set on that
    step alone, which merges them into the gate's one verdict (tests/mutants.py, WP-98) under the
    cap mutants.yml gives the same step; it uploads its slot with the report and the shard
    reports, which the merge job adopts (slots a and g) and publishes. mutants.yml runs the gate
    whole: no shard count and no --shard there. The former single job `m` is gone."""

    def jobs(self):
        return load("verify.yml")["jobs"]

    def job(self):
        jobs = self.jobs()
        self.assertIn("g", list(jobs), "verify has no merge-gate job `g`")
        return jobs["g"]

    def gate_step(self):
        steps = [s for s in self.job()["steps"] if "--suite M6-GATE" in str(s.get("run", ""))]
        self.assertEqual(len(steps), 1, "job g runs the gate suite in one step")
        return steps[0]

    def test_the_single_gate_job_m_is_gone(self):
        self.assertNotIn("m", list(self.jobs()), "job m runs the whole gate beside the shards")

    def test_the_shard_jobs_with_the_test_jobs_lab(self):
        jobs = self.jobs()
        shards = shard_jobs(jobs)
        self.assertEqual(sorted(shards), sorted(f"shard-{k}" for k in range(1, SHARDS + 1)), f"shards 1..{SHARDS}, each once")
        tool = lambda job: next(s for s in job["steps"] if str(s.get("name", "")).startswith("Toolchain"))
        for name, job in shards.items():
            self.assertEqual(shard_problems(name, job, SHARDS), [])
            steps = job["steps"]
            checkout = steps[0]
            self.assertTrue(str(checkout.get("uses", "")).startswith("actions/checkout@"))
            self.assertEqual(checkout, jobs["a"]["steps"][0], f"{name}: the checkout is not the test job's")
            self.assertEqual(tool(job)["run"], tool(jobs["a"])["run"], f"{name}: the lab is not the test job's")
            runs = [str(s.get("run", "")) for s in steps]
            gate = next(i for i, r in enumerate(runs) if "tests/mutants.py" in r)
            base = next((i for i, r in enumerate(runs) if "project.py build --target pc-qemu" in r and "project.py boot --target pc-qemu" in r), None)
            self.assertIsNotNone(base, f"{name}: no baseline build and boot of the unmutated kernel")
            self.assertLess(base, gate)
            # The baseline is a check of the lab, not evidence (the audit of WP-96): a scratch
            # root, and only there.
            for i, s in enumerate(steps):
                if i != base:
                    self.assertNotIn("NAWAH_SCRATCH_EVIDENCE", s.get("env", {}), f"{name}: only the baseline is scratch")
            self.assertNotIn("env", job, f"{name}: nothing at the job's level")

    def test_the_merge_gate_job_needs_every_shard_and_carries_the_one_verdict(self):
        jobs, g = self.jobs(), self.job()
        self.assertEqual(g.get("env", {}).get("NAWAH_RUN_SLOT"), "g")
        needs = g.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        self.assertEqual(sorted(needs), sorted(shard_jobs(jobs)), "g waits for every shard and for nothing else")
        # A failed shard still reaches the merge, which refuses it by name; a cancelled run never does.
        self.assertIn("!cancelled()", str(g.get("if", "")))
        self.assertNotIn("always()", str(g.get("if", "")))
        self.assertNotIn("write", str(g.get("permissions", {})))
        self.assertIs(g["steps"][0].get("with", {}).get("persist-credentials"), False)
        runs = [str(s.get("run", "")) for s in g["steps"]]
        suites = [l.strip() for r in runs for l in r.splitlines() if "project.py test " in l]
        self.assertEqual(suites, ["python3 tools/project.py test --target host --suite M6-GATE"], "the gate suite, and nothing else")
        self.assertFalse([r for r in runs if "tests/mutants.py" in r], "g runs no mutant")
        # This run's shard reports alone, all into the directory the merge reads (no run-id, no token).
        downloads = [i for i, s in enumerate(g["steps"]) if str(s.get("uses", "")).startswith("actions/download-artifact@")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(g["steps"][downloads[0]].get("with"),
                         {"pattern": "mutants-m6-shard-*", "path": shard_dir(), "merge-multiple": True})
        self.assertLess(downloads[0], g["steps"].index(self.gate_step()))
        self.assertEqual(self.gate_step().get("env"), {GATE_SHARDS: str(SHARDS)}, "the merge of every shard")
        self.assertIsInstance(self.gate_step()["env"][GATE_SHARDS], str)
        # The merge job adopts slots a and g (MergeJob: both loops, a missing slot fails closed).
        self.assertEqual(sorted(MergeJob.slot_problems(jobs)[0].values()), ["a", "b", "g"])

    def test_the_shard_count_is_set_on_the_gate_step_alone(self):
        # L-023: at the workflow's or g's level it would reach g's every step, and inside a
        # script it would hide from this check; mutants.yml runs the gate whole.
        doc = load("verify.yml")
        self.assertEqual(json.dumps(doc).count(GATE_SHARDS), 1, f"{GATE_SHARDS} named elsewhere than g's gate step")
        self.assertIn(GATE_SHARDS, self.gate_step().get("env", {}))
        self.assertEqual(self.gate_step()["env"][GATE_SHARDS], str(len(shard_jobs(doc["jobs"]))))
        other = json.dumps(load("mutants.yml"))
        self.assertNotIn(GATE_SHARDS, other, "mutants.yml merges shards")
        self.assertNotIn("--shard", other, "mutants.yml runs a shard")

    def test_no_other_job_runs_the_gate(self):
        # The audit of WP-96: the Suites case compares sets, so the gate added to the test
        # job's host loop or to a shard as well would run twice unnoticed (two slots, one test).
        for name, job in self.jobs().items():
            if name == "g":
                continue
            for s in job["steps"]:
                run = str(s.get("run", ""))
                self.assertNotIn("M6-GATE", run, name)
                self.assertNotRegex(run, r"for \w+ in [^;\n]*-GATE", name)

    def test_the_gate_step_is_capped_above_its_suite_timeout_as_in_mutants(self):
        step = self.gate_step()
        self.assertIn("timeout-minutes", step, "the gate step has no cap of its own")
        self.assertLess(gate_case()["timeout_s"], step["timeout-minutes"] * 60, "the suite timeout must fire before the step cap")
        other = next(s for s in next(iter(load("mutants.yml")["jobs"].values()))["steps"] if str(s.get("name", "")).startswith("Mutation run, M6"))
        self.assertEqual(step["timeout-minutes"], other["timeout-minutes"], "one cap for the same step in both workflows")

    def test_the_reports_are_uploaded_and_published(self):
        g = self.job()
        up = next(s for s in g["steps"] if s.get("with", {}).get("name") == "evidence-g")
        paths = str(up["with"].get("path", "")).split()
        report = gate_case()["command"][gate_case()["command"].index("--report") + 1]
        self.assertIn(report, paths)
        self.assertIn(shard_dir() + "/", paths, "the shard reports the verdict was merged from")
        pub = next(s for s in self.jobs()["merge"]["steps"] if str(s.get("name", "")).startswith("Publish evidence"))
        lines = [l.strip() for l in pub["run"].splitlines()]
        for x in (report, shard_dir()):
            self.assertIn(f"/usr/bin/git -c core.hooksPath=/dev/null add -f {x} 2>/dev/null || true", lines,
                          f"{x} is not on the run's evidence branch")

    def test_no_record_softens_the_gates_stale_verdict(self):
        tests = json.loads((ROOT / "docs" / "tests.json").read_text(encoding="utf-8"))["records"]
        rec = next(t for t in tests if t["id"] == "TST-M6-MUTANTS")
        self.assertNotIn("stale_policy", rec, "verify runs this gate in every run: its stale verdict is a strict error")
        self.assertNotIn("TST-M6-MUTANTS", project.STALE_WARN_TESTS)

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
    uncapped step (the build, M1-M4, the host suites, a shard's baseline) runs until the job's
    limit (G9). Besides the guest suites it reads the cap of each shard's step (`shard`) and of
    the gate suite's step in job g (`M6-GATE`), WP-152."""

    BOUNDED = ("M6",)
    # WP-83 (83a): the test job `a` is the former single job; the merge job adopts and publishes.
    # WP-88 was re-scoped to the M6 cap alone; the split of `a` into parallel jobs is WP-98's.
    # WP-96 (DEC-029): the mutation job `m`: Toolchain 15 + the gate's 135 (mutants.yml's cap for
    # the same step), x1.2 = 180; a hang guard, the gate measured 20 min on run 43615540519.
    # WP-88 (re-scoped 2026-11-14): M6 15 -> 18 and job a 58 -> 62 ((15 + 18 + 18) x 1.2 = 61.2):
    # the M6 suite's worst case stood at 895 s of the cap's 900, and the cases to come need room.
    # WP-152: job m becomes six shard jobs and the merge-gate job g. A shard's step is capped at 60,
    # a hang guard: the longest shard of the rule (k = 3, M152 and M194 alone 11 min) adds up to
    # 16.2 min of the 61.7 min of mutant time on the gate log of run 44190352865 (evidence
    # 20261117T224450Z-5d674b90-001-m, computed by reading it, never measured as a shard), so
    # (Toolchain 15 + 60) x 1.2 = 90; a shard stopped there leaves a report that never says it
    # finished, which g refuses (TST-M0-005, M299). g's gate step keeps mutants.yml's 135 for
    # the same command, above TST-M6-MUTANTS's timeout_s (the merge itself takes seconds):
    # (15 + 135) x 1.2 = 180.
    # WP-153: the M5 guest suite moves to job b, (Toolchain 15 + M5 18) x 1.2 = 39.6 -> 40; job a
    # keeps 62, a hang guard over its uncapped steps (its caps, 15 + M6 18, are 39.6 now; WP-102,
    # 15 + M6 19, 40.8; WP-167, 15 + M6 22, 44.4; WP-169, 15 + M6 24, 46.8); twelve shards keep 90 each.
    LIMITS = {"a": 62, "b": 40, **{f"shard-{k}": 90 for k in range(1, SHARDS + 1)}, "g": 180, "merge": 20}
    CAPS = {"a": {"M6": 24}, "b": {"M5": 18}, **{f"shard-{k}": {"shard": 60} for k in range(1, SHARDS + 1)},
            "g": {"M6-GATE": 135}, "merge": {}}

    def caps(self):
        jobs = load("verify.yml")["jobs"]
        caps = {}
        for name, job in jobs.items():
            caps[name] = {}
            for s in job["steps"]:
                for line in str(s.get("run", "")).splitlines():
                    m = (re.search(r"--target pc-qemu --suite (\S+)", line) or re.search(r"--target host --suite (\S+-GATE)\b", line)
                         or re.search(r"tests/mutants\.py .*--(shard) ", line))
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


DEFAULT_STAGES = "M2 M3 M4 M5"


class MutationHarness(unittest.TestCase):
    def test_mutants_runs_the_gates_in_order_and_publishes_every_report(self):
        # WP-38 phase 1 (2026-10-28): the M5 step was added but its report was left out of the
        # evidence branch's `git add`, and no test held the gate order; the records check
        # before the runs was not strict.
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        names = [str(s.get("name", "")) for s in steps]
        gates = [n for n in names if n.startswith("Mutation run, ")]
        self.assertEqual([g.split(",")[1].strip()[:2] for g in gates], ["M2", "M3", "M4", "M5", "M6"],
                         "the gates run in order M2, M3, M4, M5, M6 (WP-90 adds M6)")
        runs = [s["run"] for s in steps if str(s.get("name", "")).startswith("Mutation run, ")]
        self.assertEqual(runs, [f"python3 tools/project.py test --target host --suite {x}" for x in ("M2", "M3-GATE", "M4-GATE", "M5-GATE", "M6-GATE")])
        # A failed gate must not skip the next, only the selected gates run, and none runs after a
        # failed baseline (always() let M3..M6 run on an image that never built or booted; WP-95,
        # the assurance review of 2026-11-15) nor in a cancelled run.
        base = [i for i, s in enumerate(steps) if s.get("id") == "baseline"]
        self.assertEqual(len(base), 1, "the baseline step has no id the gates can test")
        baseline = steps[base[0]]
        self.assertIn("project.py build --target pc-qemu", baseline["run"])
        self.assertIn("project.py boot --target pc-qemu", baseline["run"])
        self.assertNotIn("if", baseline, "the baseline runs only after the steps before it succeeded")
        self.assertNotIn("continue-on-error", baseline)
        for i, s in enumerate(steps):
            if str(s.get("name", "")).startswith("Mutation run, "):
                stage = s["name"].split(",")[1].strip()[:2]
                want = (f"${{{{ !cancelled() && steps.baseline.outcome == 'success' && "
                        f"contains(format(' {{0}} ', inputs.stages || '{DEFAULT_STAGES}'), ' {stage} ') }}}}")
                self.assertEqual(s.get("if"), want, f"{s['name']}: its condition")
                self.assertGreater(i, base[0])

        # WP-90 (audit of WP-92): strict validation before the gates deadlocks when a gate's oracle
        # text changes (its PASS cites evidence with the old oracle, and only a successful run of
        # this workflow can bring new evidence). The check before the gates is the non-strict one
        # (as verify's); the strict one runs after the last gate, over the run's native evidence.
        validate = [(i, s) for i, s in enumerate(steps) if str(s.get("name", "")).startswith("validate-records")]
        self.assertEqual(len(validate), 2, "one records check before the gates, one after")
        gate_idx = [i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Mutation run, ")]
        (pre_i, pre), (post_i, post) = validate
        self.assertLess(pre_i, min(gate_idx))
        self.assertEqual(pre["run"].strip(), "python3 tools/project.py validate-records", "the check before the gates is not strict")
        self.assertGreater(post_i, max(gate_idx))
        self.assertEqual(post["run"].strip(), "python3 tools/project.py validate-records --strict")
        self.assertEqual(post.get("if"), "always()", "the strict check reports even after a red gate")
        publish_i = next(i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Publish evidence"))
        self.assertLess(post_i, publish_i)
        publish = next(s for s in steps if str(s.get("name", "")).startswith("Publish evidence"))
        run = publish["run"]
        self.assertIn("git add -f evidence/", run)
        # Run 42481065666: one `git add` of every report failed when M2 had none, and the M5
        # report was lost with it; each report is added on its own, if it exists.
        self.assertNotRegex(run, r"git add -f evidence/ build/", "one missing report must not drop the others")
        loop = next(l for l in run.splitlines() if l.strip().startswith("for r in "))
        self.assertIn('if [ -f "$r" ]; then git add -f "$r"; fi', run)
        upload = next(s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
        for rep in ("build/mutants-report.json", "build/mutants-m3-report.json", "build/mutants-m4-report.json",
                    "build/mutants-m5-report.json", "build/mutants-m6-report.json"):
            self.assertIn(rep, loop, f"{rep} is not published on the evidence branch")
            self.assertIn(rep, upload["with"]["path"], f"{rep} is not in the uploaded artifact")

    def test_the_default_stages_are_m2_to_m5_because_verify_runs_m6(self):
        # WP-90 (review condition 7) chose the stages by a workflow_dispatch input, M6 out of the
        # default until it was green. WP-95 (the manager, 2026-11-18): it stays out, now because
        # verify runs the M6 gate in every run (the owner's DEC-029, WP-96; in shards since WP-152
        # and WP-153), so the schedule and the default run exactly M2 M3 M4 M5, the gates verify
        # does not run (STALE_WARN_TESTS), and a dispatch names M6 to run it here.
        on = load("mutants.yml")["on"]
        inp = on["workflow_dispatch"]["inputs"]["stages"]
        self.assertEqual((inp.get("type"), inp.get("default")), ("string", DEFAULT_STAGES))
        self.assertEqual(DEFAULT_STAGES, "M2 M3 M4 M5")
        self.assertIn("schedule", on, "the scheduled run takes the default")
        gate_ids = {c["id"] for s in ("M2", "M3-GATE", "M4-GATE", "M5-GATE") for c in project.HOST_SUITES[s]
                    if "tests/mutants.py" in c["command"]}
        self.assertEqual(gate_ids, set(project.STALE_WARN_TESTS), "the default's gates are the ones verify does not run")
        verify = load("verify.yml")
        self.assertIn("push", verify[True] if True in verify else verify["on"])
        runs = [l.strip() for j in verify["jobs"].values() for s in j["steps"] for l in str(s.get("run", "")).splitlines()]
        self.assertIn("python3 tools/project.py test --target host --suite M6-GATE", runs, "verify does not run the M6 gate")

    def test_the_artifact_holds_this_runs_directories_alone(self):
        # The WP-95 review (F7, A-L08, RT95-07): `evidence/` uploaded the whole tracked evidence
        # tree (14.4 GB) uncapped. As verify since WP-153: an always() step `rev` before the
        # upload, the run's own directories (no slot in mutants.yml: <stamp>-<sha8>-<nnn>), the
        # artifact rooted at the workspace (artifact_root) and the step capped. Publish, the
        # ci-evidence branch import-ci-evidence reads, is unchanged.
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        ups = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
        self.assertEqual(len(ups), 1)
        up = steps[ups[0]]
        paths = upload_paths(up)
        ev = [x for x in paths if x.startswith("evidence")]
        self.assertEqual(ev, ["evidence/*-${{ steps.rev.outputs.sha8 }}-*/"], "not this run's directories alone")
        self.assertEqual(artifact_root(paths), "", "the artifact is not rooted at the workspace")
        self.assertIn("timeout-minutes", up, "the upload has no cap")
        self.assertIn("always()", str(up.get("if", "")))
        revs = [i for i, s in enumerate(steps) if s.get("id") == "rev"]
        self.assertEqual(len(revs), 1)
        self.assertLess(revs[0], ups[0])
        self.assertEqual(steps[revs[0]].get("run"), REV_RUN)
        self.assertIn("always()", str(steps[revs[0]].get("if", "")))
        sha8 = project.source_identity()[0][:8]
        other = "0" * 8 if sha8 != "0" * 8 else "1" * 8
        pattern = ev[0].replace("${{ steps.rev.outputs.sha8 }}", sha8)
        self.assertTrue(fnmatch.fnmatchcase(f"evidence/20261118T035023Z-{sha8}-002/", pattern))
        self.assertFalse(fnmatch.fnmatchcase(f"evidence/20261118T035023Z-{other}-002/", pattern))
        committed = subprocess.run(["git", "ls-tree", "--name-only", "HEAD", "evidence/"], cwd=ROOT,
                                   capture_output=True, text=True).stdout.split()
        self.assertEqual([c for c in committed if fnmatch.fnmatchcase(c.rstrip("/") + "/", pattern)], [])
        publish = next(s for s in steps if str(s.get("name", "")).startswith("Publish evidence"))
        self.assertIn("git add -f evidence/", publish["run"], "the evidence branch no longer carries the tree")

    def stages_step(self):
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        found = [i for i, s in enumerate(steps) if s.get("id") == "stages"]
        self.assertEqual(len(found), 1, "mutants.yml has no step `stages` checking the selection")
        return found[0], steps

    def run_stages(self, value):
        i, steps = self.stages_step()
        r = subprocess.run(["bash", "-e", "-c", steps[i]["run"]], env=dict(os.environ, STAGES=value), capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_a_dispatch_that_selects_no_gate_fails(self):
        # WP-95 (the assurance review of 2026-11-15): `stages` naming no gate (a typo, a comma,
        # lower case) ran no gate and ended green, with nothing to import. The step runs before the
        # toolchain, reads the input through the environment (never spliced into the script) with
        # the gates' own default, and refuses any word that names no gate.
        i, steps = self.stages_step()
        step = steps[i]
        self.assertEqual(step.get("env"), {"STAGES": f"${{{{ inputs.stages || '{DEFAULT_STAGES}' }}}}"})
        self.assertNotIn("inputs.", step["run"], "the input is spliced into the script")
        tool = next(j for j, s in enumerate(steps) if str(s.get("name", "")).startswith("Toolchain"))
        self.assertLess(i, tool, "the selection is checked before the toolchain")
        self.assertNotIn("if", step)
        gates = [s["name"].split(",")[1].strip()[:2] for s in steps if str(s.get("name", "")).startswith("Mutation run, ")]
        for ok in [DEFAULT_STAGES, " ".join(gates), "M6", "M3", "M2  M5", "M6 M2"] + gates:
            rc, out = self.run_stages(ok)
            self.assertEqual(rc, 0, f"{ok!r}: {out}")
        # The WP-95 review (A-L02, F1, RT95-01): a tab or a newline splits the words for the
        # shell's loop but not for each gate's contains(' M3 '), so the run passed with no gate.
        for bad in (" ", "M7", "m2", "M2,M3", "M1", "M3 M7", "*", "M2 -M3", "all", "M2\tM3", "M2\nM5", "M6\n"):
            rc, out = self.run_stages(bad)
            self.assertNotEqual(rc, 0, f"{bad!r} accepted")
            self.assertIn("::error", out, bad)
    # The four older gates measured 30.1 + 21.9 + 29.3 + 46.5 = 127.8 min (their evidence of
    # 2026-11-08/09, 20261108T223908Z-2cbdeaad-001 to 20261109T000029Z-2cbdeaad-001); uncapped,
    # each bounded by its suite's timeout_s.
    OLDER_GATES_MEASURED_MIN = 127.8
    HOSTED_JOB_MAX_MIN = 360  # GitHub-hosted runners end a job at 6 hours

    def test_the_m6_gate_is_time_boxed_inside_the_job(self):
        # WP-90: the M6 gate's suite timeout ends it with a verdict and the partial report before
        # its step cap. WP-95: the job's limit fits every step of a run of all five gates: each
        # capped step at its cap (Toolchain, the M6 gate, the host suites), the four uncapped older
        # gates at their measured time with the 20 % margin, 20 min for the rest (checkout,
        # baseline, records checks, report, publish), and stays within a hosted job's maximum.
        job = next(iter(load("mutants.yml")["jobs"].values()))
        step = next(s for s in job["steps"] if str(s.get("name", "")).startswith("Mutation run, M6"))
        self.assertIn("timeout-minutes", step, "the M6 gate step has no cap of its own")
        case = next(c for c in project.HOST_SUITES["M6-GATE"] if c["id"] == "TST-M6-MUTANTS")
        self.assertLess(case["timeout_s"], step["timeout-minutes"] * 60, "the suite timeout must fire before the step cap")
        caps = [s["timeout-minutes"] for s in job["steps"] if "timeout-minutes" in s]
        older = [s for s in job["steps"] if str(s.get("name", "")).startswith("Mutation run, M") and "timeout-minutes" not in s]
        self.assertEqual(len(older), 4, "M2 to M5 run uncapped, bounded by their suites' timeout_s")
        need = sum(caps) + 1.2 * self.OLDER_GATES_MEASURED_MIN + 20
        self.assertLessEqual(need, job["timeout-minutes"], f"the steps need {need:.0f} min of the job's {job['timeout-minutes']}")
        self.assertLessEqual(job["timeout-minutes"], self.HOSTED_JOB_MAX_MIN)

    def test_mutants_runs_verifys_host_suites_after_the_gates_before_the_strict_check(self):
        # WP-95 (option B, the manager, 2026-11-18): a run of mutants.yml is imported only when its
        # strict check passes over the head it ran on, and a head that changes tools/project.py or
        # the harness leaves every host test stale but the gates. So mutants.yml runs every host
        # suite verify runs, with verify's own script (WP-91: each suite once, the step failing at
        # the end when any failed), after the last gate (a red gate does not skip it, a cancelled
        # run does) and before the strict check, under a cap of its own; and its lab is verify's.
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        host = [i for i, s in enumerate(steps) if str(s.get("name", "")) == "Host suites"]
        self.assertEqual(len(host), 1, "mutants.yml has no Host suites step")
        mine = steps[host[0]]
        self.assertEqual(mine["run"], HostStep().step()["run"], "not verify's Host suites script")
        self.assertEqual(HostStep().problems(script=mine["run"]), [])
        self.assertEqual(mine.get("if"), "${{ !cancelled() && steps.baseline.outcome == 'success' }}",
                         "the host suites run after a red gate, never after a failed baseline nor in a cancelled run")
        self.assertIn("timeout-minutes", mine)
        gates = [i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Mutation run, ")]
        strict = next(i for i, s in enumerate(steps) if str(s.get("run", "")).strip() == "python3 tools/project.py validate-records --strict")
        self.assertLess(max(gates), host[0])
        self.assertEqual(strict, host[0] + 1, "the strict check comes right after the host suites")
        tool = lambda doc_steps: next(s for s in doc_steps if str(s.get("name", "")).startswith("Toolchain"))
        self.assertEqual(tool(steps)["run"], tool(load("verify.yml")["jobs"]["a"]["steps"])["run"],
                         "mutants.yml's lab is not verify's (the host suites need fonttools, harfbuzz and the rest)")

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
