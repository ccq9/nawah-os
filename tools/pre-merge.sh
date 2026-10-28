#!/usr/bin/env bash
# The gate a records commit passes before it is committed or merged (WP-38, 2026-10-28).
#
# Two records commits (2026-10-27, 2026-10-28) carried 11 strict errors each because the
# chain `validate-records --strict | tail -1 && git commit` lost the validator's exit code in
# the pipe. Here the validator's own code is the script's: no pipe stands between them, and
# -e, -u and pipefail make any failing command end the script. Use it as
#     tools/pre-merge.sh && git commit ...
# and in CI before the status report (verify.yml).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="${NAWAH_ROOT:-$root}"
cd "$root"

python3 tools/project.py validate-records --strict
echo "pre-merge: OK (validate-records --strict reported 0 errors)"
