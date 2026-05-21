#!/usr/bin/env bash
# integ-docs-gate.sh
#
# PreToolUse hook. Blocks `gh pr create` and `gh pr merge` unless the
# `integ-docs` markgate marker is fresh for the current content of
# .claude/skills/integ-test/SKILL.md, test/integ/README.md, and
# scripts/integ.sh (see .markgate.yml).
#
# To unblock: edit the offending files into consistency, then run the
# /verify-integ-docs skill (which calls scripts/verify-integ-docs.sh
# and, on pass, `markgate set integ-docs`).

set -u

# Resolve repo root from script location (.claude/hooks/integ-docs-gate.sh -> repo root).
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

# Prefer mise-pinned markgate (.mise.toml) so the schema version matches
# what the rest of the repo expects. Fall back to PATH binary.
if command -v mise >/dev/null 2>&1; then
  markgate=(mise exec -- markgate)
elif command -v markgate >/dev/null 2>&1; then
  markgate=(markgate)
else
  cat >&2 <<EOF
Blocked by integ-docs-gate: markgate is not installed.

Install via mise (preferred — matches the version pinned in .mise.toml):
  mise install

Or install markgate via your packager (Homebrew, ubi, source).
EOF
  exit 2
fi

if "${markgate[@]}" verify integ-docs >/dev/null 2>&1; then
  exit 0
fi

cat >&2 <<EOF
Blocked by integ-docs-gate: \`integ-docs\` markgate marker is stale or missing.

The skill (.claude/skills/integ-test/SKILL.md) and README
(test/integ/README.md) document the same workflow for two different
audiences (Claude / human). If they drift, a human following the README
hits a different code path than Claude following the skill — and bugs in
one don't surface in the other.

To unblock:

  1. Run the consistency check:
       ./scripts/verify-integ-docs.sh

  2. Fix any drift it reports.

  3. Flip the marker:
       mise exec -- markgate set integ-docs

     (Or invoke the /verify-integ-docs skill, which does steps 1+3.)

If you genuinely have an emergency PR that has nothing to do with the
integ docs (and you confirmed they didn't drift), you can also just run
\`markgate set integ-docs\` directly — the marker just records that the
files agree with whatever set-time content they had.
EOF
exit 2
