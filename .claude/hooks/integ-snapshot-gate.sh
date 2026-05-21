#!/usr/bin/env bash
# integ-snapshot-gate.sh
#
# PreToolUse hook. Blocks `gh pr create` and `gh pr merge` unless the
# `integ-snapshot-fresh` markgate marker is fresh for the current
# content of src/, assets/lambda/, Dockerfile, etc. (see .markgate.yml).
#
# Triggered automatically by `.claude/settings.json`. The marker is set
# by the /integ-test skill after a clean `all` mode run (basic +
# enhanced + signature all PASS).
#
# To unblock: run the /integ-test skill with `all` mode against real
# AWS, then `markgate set integ-snapshot-fresh` (the skill does the
# `markgate set` step automatically on a clean run).

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cmd=$(jq -r '.tool_input.command // ""' 2>/dev/null || echo "")

# Only gate `gh pr create` and `gh pr merge` — any other Bash invocation
# passes through.
#
# IMPORTANT: anchor `gh pr (create|merge)` to the START of a command
# (string start, or after a chain operator `&&`, `||`, `;`, `|`), NOT
# anywhere in the body. Otherwise the hook false-positives on commands
# whose heredoc bodies / quoted arguments simply mention those phrases
# (e.g. `git commit -m "describe gh pr create behavior"`).
if ! printf '%s' "$cmd" | grep -qE '(^|(&&|\|\||;|\|)[[:space:]]*)gh[[:space:]]+pr[[:space:]]+(create|merge)([[:space:]]|$)'; then
  exit 0
fi

cd "$REPO" 2>/dev/null || exit 0

if command -v mise >/dev/null 2>&1; then
  markgate=(mise exec -- markgate)
elif command -v markgate >/dev/null 2>&1; then
  markgate=(markgate)
else
  cat >&2 <<EOF
Blocked by integ-snapshot-gate: markgate is not installed.

Install via mise (preferred):
  mise install

Or install markgate via your packager.
EOF
  exit 2
fi

if "${markgate[@]}" verify integ-snapshot-fresh >/dev/null 2>&1; then
  exit 0
fi

cat >&2 <<EOF
Blocked by integ-snapshot-gate: \`integ-snapshot-fresh\` markgate marker is stale or missing.

The CDK source (src/) or Lambda asset (assets/lambda/) has changed since
the last successful integ-test run. Any of these changes will alter the
Lambda image asset hash or CloudFormation template, so the recorded integ
snapshots in test/integ/ are out of date and CI will fail.

To unblock:

  1. Run the /integ-test skill in \`all\` mode against real AWS:
       (in Claude Code)  /integ-test all

     The skill orchestrates Inspector enable/disable, scan-on-push,
     signature setups, and snapshot regeneration end-to-end, and runs
     \`markgate set integ-snapshot-fresh\` automatically on a clean pass.

  2. Commit the regenerated snapshots under test/integ/.

  3. Retry \`gh pr create\` / \`gh pr merge\`.

If you genuinely have NOT changed anything that affects integ snapshots
(e.g. docs-only edits to JSDoc that don't change template output) and
CI is going to be green anyway, you can mark the gate fresh without a
re-run:

       mise exec -- markgate set integ-snapshot-fresh

But verify CI actually goes green before merging — this bypass exists
for edge cases, not as a routine shortcut.
EOF
exit 2
