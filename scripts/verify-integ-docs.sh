#!/usr/bin/env bash
# verify-integ-docs.sh
#
# Verifies that the three sources documenting the integ workflow stay in
# sync with each other:
#
#   .claude/skills/integ-test/SKILL.md  — automated (Claude Code skill)
#   test/integ/README.md                 — manual (human-readable docs)
#   scripts/integ.sh                     — shell helpers shared by both
#
# Both docs must exist (skill = automated, README = manual; deleting one
# would leave the other lying about its counterpart). Both must mention
# every helper that lives in scripts/integ.sh, and both must agree on
# the mode list.
#
# Run via the /verify-integ-docs skill, which flips the `integ-docs`
# markgate marker after this passes.

set -u

SKILL=".claude/skills/integ-test/SKILL.md"
README="test/integ/README.md"
HELPERS="scripts/integ.sh"

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
ok()   { echo "ok:   $*"; }

# --- 1. Source files exist --------------------------------------------------

for f in "$SKILL" "$README" "$HELPERS"; do
  if [ ! -f "$f" ]; then
    fail "missing source file: $f"
  fi
done
[ "$fails" -eq 0 ] || { echo "Aborting; source files missing." >&2; exit 1; }
ok "all three source files exist"

# --- 2. Mode parity ---------------------------------------------------------
# Every mode in the skill's argument-hint must appear in both:
#   - the SKILL's `## Arguments` list (one `- \`mode\` — desc` line each)
#   - the README's `### Modes` table (one `| \`mode\` |` row each)

modes_line=$(grep -E '^argument-hint:' "$SKILL" | head -1)
modes=$(printf '%s\n' "$modes_line" | grep -oE '<[^>]+>' | head -1 | tr -d '<>' | tr '|' '\n')

if [ -z "$modes" ]; then
  fail "could not parse modes from SKILL argument-hint"
else
  for mode in $modes; do
    grep -qE "^- \`$mode\`" "$SKILL" \
      || fail "mode '$mode' in argument-hint but missing from SKILL '## Arguments' list"
    grep -qE "\| \`$mode\` \|" "$README" \
      || fail "mode '$mode' in argument-hint but missing from README modes table"
  done
  [ "$fails" -gt 0 ] || ok "all argument-hint modes present in SKILL Arguments + README table"
fi

# --- 3. Helper function parity ---------------------------------------------
# Every shell function defined in scripts/integ.sh should be referenced
# from at least one of SKILL/README (catches dead helpers and rename drift).

functions=$(grep -E '^[a-z_][a-z0-9_]*\(\)' "$HELPERS" | sed 's/().*//')
if [ -z "$functions" ]; then
  fail "could not parse any functions from $HELPERS"
else
  for fn in $functions; do
    if ! grep -qw "$fn" "$SKILL" && ! grep -qw "$fn" "$README"; then
      fail "helper '$fn' defined in $HELPERS but not referenced from SKILL or README"
    fi
  done
  [ "$fails" -gt 0 ] || ok "every helper function is referenced from at least one doc"
fi

# --- 4. Both docs reference scripts/integ.sh -------------------------------

for f in "$SKILL" "$README"; do
  grep -q "scripts/integ.sh" "$f" \
    || fail "$f does not reference scripts/integ.sh"
done
[ "$fails" -gt 0 ] || ok "both docs reference scripts/integ.sh"

# --- 5. No raw `aws signer put-signing-profile` ----------------------------
# Raw form is NOT idempotent (returns ProfileAlreadyExists on existing
# Active profile). Use signer_profile_ensure instead.

for f in "$SKILL" "$README"; do
  if grep -nE "aws signer put-signing-profile" "$f" >/dev/null; then
    fail "$f has raw 'aws signer put-signing-profile' — use signer_profile_ensure (raw form is NOT idempotent)"
  fi
done

# --- 6. No insufficient signing-config jq strip ----------------------------
# cosign 3.x silently hangs when --key is combined with a signing-config
# that still has oidc/ca/tsa fields. The correct strip is rekor+oidc+ca+tsa,
# which lives in cosign_minimal_signing_config.

for f in "$SKILL" "$README"; do
  # Match `jq 'del(.rekorTlogUrls)'` (the OLD broken strip) — but not
  # `del(.rekorTlogUrls, .oidcUrls, .caUrls, .tsaUrls)` (the helper's correct strip).
  if grep -E "del\(\\.rekorTlogUrls\)" "$f" >/dev/null; then
    fail "$f has insufficient 'del(.rekorTlogUrls)' — use cosign_minimal_signing_config (also strips oidc/ca/tsa)"
  fi
done

# --- 7. signature mode list matches integ.signature/integ.<name>.js -------
# For every signature-* mode, the referenced integ test file must exist.

for mode in $(printf '%s\n' "$modes" | grep '^signature-'); do
  # signature-notation -> test/integ/signature/integ.notation.js
  fname=$(printf '%s' "$mode" | sed 's/^signature-//')
  testfile="test/integ/signature/integ.${fname}.js"
  if [ ! -f "$testfile" ]; then
    fail "mode '$mode' references missing test file $testfile"
  fi
done

# --- 8. Final report -------------------------------------------------------

if [ "$fails" -gt 0 ]; then
  echo "" >&2
  echo "verify-integ-docs: $fails failure(s). Fix above before setting integ-docs marker." >&2
  exit 1
fi

echo ""
echo "verify-integ-docs: all consistency checks passed."
