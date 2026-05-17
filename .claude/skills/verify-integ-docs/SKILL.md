---
name: verify-integ-docs
description: Verify the integ-test skill, test/integ/README.md, and scripts/integ.sh stay consistent. Runs the mechanical script checks PLUS LLM-only semantic checks (mode-description agreement, code-example coherence, cross-reference resolution, depth parity, helper-arg correctness) that a regex can't catch. Sets the `integ-docs` markgate marker on full pass.
---

# verify-integ-docs

The integ workflow is documented in three places that must agree:

| Source                              | Audience               |
| ----------------------------------- | ---------------------- |
| `.claude/skills/integ-test/SKILL.md`| Claude Code (automated)|
| `test/integ/README.md`              | humans (manual runs)   |
| `scripts/integ.sh`                  | shared shell helpers   |

Both docs are intentionally redundant — the skill drives Claude through the workflow, the README lets a human run the same workflow by hand. This skill keeps them in lockstep using **two layers**:

1. **Mechanical** (`scripts/verify-integ-docs.sh`) — name parity, dead-helper detection, anti-pattern grep. Cheap, deterministic, runnable in CI.
2. **Semantic** (this skill) — does each mode actually mean the same thing in both docs? Do code examples produce equivalent results? Are cross-references valid? Only an LLM that reads both docs side-by-side can answer these.

Both layers must pass before the marker flips. If only the mechanical layer matters, use `markgate run integ-docs -- ./scripts/verify-integ-docs.sh` directly instead of this skill — but you'll miss the kinds of drift listed under "Semantic checks" below.

## Layer 1: mechanical (script)

`scripts/verify-integ-docs.sh` enforces:

1. **All three source files exist** — deleting one without the other would leave stale references.
2. **Mode parity** — every mode in the SKILL's `argument-hint:` frontmatter must appear in both the SKILL's `## Arguments` list AND the README's `### Modes` table.
3. **Helper parity** — every function defined in `scripts/integ.sh` must be referenced from at least one of the two docs (catches dead helpers and rename drift).
4. **Both docs source the helpers** — both must reference `scripts/integ.sh`.
5. **No raw `aws signer put-signing-profile`** — it's NOT idempotent (returns `ProfileAlreadyExists` on existing Active profile). Must use `signer_profile_ensure`.
6. **No insufficient cosign signing-config strip** — `del(.rekorTlogUrls)` alone causes cosign 3.x to silently hang on `--key` signing. Must use `cosign_minimal_signing_config` (also strips oidc / ca / tsa).
7. **`signature-*` mode test sources exist** — every `signature-<name>` mode must have a corresponding `test/integ/signature/integ.<name>.ts`.

```bash
./scripts/verify-integ-docs.sh
```

If it fails, fix the reported drift first; do NOT proceed to layer 2 or set the marker.

## Layer 2: semantic (this skill, LLM-only)

Run these AFTER layer 1 passes. Each catches a class of drift the script cannot.

### S1. Per-mode description agreement

For each mode in `argument-hint:`, compare:

- the SKILL's `## Arguments` line: `` - `mode` — <SKILL description> ``
- the README's `### Modes` table row: `` | `mode` | <README description> | ``

These are written for different audiences (LLM vs human), so they should NOT be byte-identical. They MUST claim the same behavior. Flag drift such as:

- **Contradictory claims**: SKILL says "switch Inspector if needed, run …, restore" but README says "Run …; no Inspector toggle" → one is wrong.
- **Coverage mismatch**: SKILL describes 3 sub-steps, README describes only 1 → README is misleading; either expand it or compress the SKILL.
- **Out-of-date defaults**: SKILL says "deploys by default" but README says "snapshot-only by default" → polarity skew.

### S2. Code-example coherence

For each mode that has a code example in BOTH docs (notation, cosign-kms, cosign-publickey, ecr-signing), read the SKILL and README versions side-by-side and verify they would produce the same result:

- Same commands in the same order (allow trivial reordering only when results are independent).
- Same flags (e.g., `--region "${REGION}"` vs no region).
- Same helper invocations (e.g., both use `signer_profile_ensure`, not one with `aws signer put-signing-profile`).
- Same env vars (`COSIGN_PASSWORD=""` present in both, etc.).

If they diverge, ask: which is right? Usually the SKILL (more recently audited) — port the change to the README, or vice versa.

### S3. Cross-reference resolution

Every markdown link of the form `[text](#anchor)` in SKILL.md or README.md must resolve to an actual heading in the same document. Common breaks:

- Heading renamed but the anchor link not updated.
- Anchor uses underscore where the heading slug uses hyphen.
- Link refers to a section that exists in the OTHER doc (not the same one).

Also check that `[text](../../scripts/integ.sh)` and similar relative paths actually resolve from the doc's location.

### S4. Helper-argument correctness

For each helper from `scripts/integ.sh` that appears in either doc, confirm the call sites use valid arguments:

- `scan_on_push_set true|false` — not `enable` / `on` / `yes`.
- `wait_inspector_status_all ENABLED|DISABLED` — uppercase string literals.
- `wait_enhanced_engine_warmup ENABLED|DISABLED [secs]` — same.
- `signer_profile_ensure` — no args.

The script's helper-parity check (mechanical #3) only verifies the **name** is mentioned; it cannot check the **arguments**.

### S5. Depth parity

For each mode, neither doc's explanation should be more than ~3× the length of the other. The two are for different audiences, but a 1-line README row plus a 50-line SKILL section means the README is silently lying about how complex the mode is. Flag and either expand the shorter side or trim the longer.

### S6. Drift in "Important" / gotcha lists

Compare the bullet lists at the end of each doc ("Important", "Important Note", trailing tips). Any caveat present in one but missing from the other is a candidate for porting. Examples that have bitten us before:

- "Bootstrap repo uses immutable tags — must delete leftover Notation referrer tag before retrying"
- "cosign 3.x signing-config needs oidc/ca/tsa stripped, not just rekor"
- "AWS Signer profile cancellation is permanent"

If any of those appear in one doc but not the other, port them.

## When to run

- After editing any of `.claude/skills/integ-test/SKILL.md`, `test/integ/README.md`, or `scripts/integ.sh`.
- The `integ-docs-gate.sh` PreToolUse hook blocks `gh pr create` / `gh pr merge` when the marker is stale, so a missed run surfaces at PR time.
- The `.github/workflows/verify-integ-docs.yml` workflow runs the mechanical script on every PR. **It does NOT run the semantic checks above** — those still require this skill (an LLM). CI catches the cheap drift; the skill catches the expensive drift.

## Setting the marker

ONLY after both layer 1 (script) and layer 2 (S1–S6) pass:

```bash
if command -v mise >/dev/null 2>&1; then
  mise exec -- markgate set integ-docs
else
  markgate set integ-docs
fi
```

If layer 1 failed → fix mechanical drift, re-run. If any semantic check (S1–S6) flagged something → fix the underlying doc drift (or surface to the user when the right answer isn't obvious), THEN set the marker. Setting the marker on a failed run defeats the entire gate.

## Recovery from drift

The most common failures and their fixes:

- **Mode missing from one doc** (mech #2): add it to the missing place. Don't remove it from the other.
- **Helper not referenced** (mech #3): either reference it from the appropriate doc OR delete it from `scripts/integ.sh` if truly unused.
- **Raw `put-signing-profile`** (mech #5): replace with `signer_profile_ensure`.
- **Raw `del(.rekorTlogUrls)`** (mech #6): replace with `cosign_minimal_signing_config /tmp/signing-config.json`.
- **Signature mode without matching test** (mech #7): either add the test (`test/integ/signature/integ.<name>.ts` + build), or remove the mode from the skill and README.
- **Per-mode description disagreement** (sem S1): pick the audience-appropriate wording for each, but make sure they describe the same behavior. Don't silently delete claims to "fix" the diff.
- **Code example divergence** (sem S2): identify which version was changed last (git blame) and port to the other.
- **Broken cross-reference** (sem S3): fix the anchor or rename the heading consistently.
- **Wrong helper arg** (sem S4): fix the call site — the helper's contract is authoritative, not the doc.
- **Depth imbalance** (sem S5): usually expand the README (the human audience needs MORE detail, not less, even though the SKILL can be terse with LLM context).
- **Caveat in one doc only** (sem S6): port it.

## Important

- **Layer 2 is the skill's reason to exist.** If you only run the script, prefer `markgate run integ-docs -- ./scripts/verify-integ-docs.sh` and skip this skill entirely. The skill's value is doing what `grep` can't.
- **Never set the marker on a failed run.** The gate's whole point is that the marker is an audit trail saying "yes, these files agree, and I personally read them." Setting it to silence a failure is the worst possible move.
- **Adding a new helper to `scripts/integ.sh`** requires using it from at least one doc in the same change (mechanical check), AND documenting its arg contract (semantic check S4).
- **Adding a new integ test file** alone does NOT invalidate the marker (only SKILL.md / README.md / scripts/integ.sh do, per `.markgate.yml` scope). New tests typically come with README changes anyway, which trip the marker naturally.
