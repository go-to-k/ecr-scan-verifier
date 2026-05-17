---
name: verify-integ-docs
description: Verify the integ-test skill, test/integ/README.md, and scripts/integ.sh stay consistent (mode parity, helper parity, no raw idempotency anti-patterns). Run after editing any of those three files. Flips the `integ-docs` markgate marker on success so subsequent `gh pr create`/`merge` invocations pass the integ-docs-gate hook.
---

# verify-integ-docs

The integ workflow is documented in three places that must agree:

| Source                              | Audience               |
| ----------------------------------- | ---------------------- |
| `.claude/skills/integ-test/SKILL.md`| Claude Code (automated)|
| `test/integ/README.md`              | humans (manual runs)   |
| `scripts/integ.sh`                  | shared shell helpers   |

Both docs are intentionally redundant — the skill drives Claude through the workflow, the README lets a human run the same workflow by hand. This skill keeps them in lockstep.

## What it checks

`scripts/verify-integ-docs.sh` enforces the following invariants:

1. **All three source files exist** — deleting one without the other would leave stale references.
2. **Mode parity** — every mode in the SKILL's `argument-hint:` frontmatter must appear in both the SKILL's `## Arguments` list AND the README's `### Modes` table.
3. **Helper parity** — every function defined in `scripts/integ.sh` must be referenced from at least one of the two docs (catches dead helpers and rename drift).
4. **Both docs source the helpers** — both must reference `scripts/integ.sh`.
5. **No raw `aws signer put-signing-profile`** — it's NOT idempotent (returns `ProfileAlreadyExists` on existing Active profile). Must use `signer_profile_ensure`.
6. **No insufficient cosign signing-config strip** — `del(.rekorTlogUrls)` alone causes cosign 3.x to silently hang on `--key` signing. Must use `cosign_minimal_signing_config` (also strips oidc / ca / tsa).
7. **`signature-*` mode test files exist** — every `signature-<name>` mode must have a corresponding `test/integ/signature/integ.<name>.js`.

## When to run

- After editing any of `.claude/skills/integ-test/SKILL.md`, `test/integ/README.md`, or `scripts/integ.sh`.
- The `integ-docs-gate.sh` PreToolUse hook blocks `gh pr create` / `gh pr merge` when the marker is stale for the current content of those files, so a missed run surfaces at PR time.
- The `.github/workflows/verify-integ-docs.yml` workflow runs `scripts/verify-integ-docs.sh` on every pull request, so contributors who don't use Claude Code (or any pre-tool hook) still get blocked at the CI level.

## How

```bash
./scripts/verify-integ-docs.sh
```

If it passes (exit 0), flip the markgate marker so the hook lets PR commands through:

```bash
# Prefer mise-pinned markgate so everyone is on the same schema version
# (cdkd has been bit by Homebrew vs mise version skew — same risk here once
# someone else installs a different markgate locally). Fall back to PATH.
if command -v mise >/dev/null 2>&1; then
  mise exec -- markgate set integ-docs
else
  markgate set integ-docs
fi
```

If it fails, fix the reported drift first — do NOT set the marker to work around a failure. The whole point of the gate is that the marker is the audit trail saying "yes, these files agree."

## Recovery from drift

The most common failures and their fixes:

- **Mode missing from one doc**: add it to the missing place. Don't remove it from the other.
- **Helper not referenced**: either reference it from the appropriate doc OR delete it from `scripts/integ.sh` if truly unused.
- **Raw `put-signing-profile` in docs**: replace with `signer_profile_ensure` (don't try to add `|| true` — the helper does get-or-create which is the correct semantic).
- **Raw `del(.rekorTlogUrls)`**: replace with `cosign_minimal_signing_config /tmp/signing-config.json`.
- **Signature mode without matching test**: either add the test (`test/integ/signature/integ.<name>.ts` + build), or remove the mode from the skill and README.

## Important

- **Never bypass with `--no-verify`** on git commit, etc. The gate exists because doc drift between SKILL.md and README.md silently makes the workflow misleading — a human following the README hits a different code path than Claude following the skill, and bugs in one don't surface in the other.
- **Adding a new helper to `scripts/integ.sh`** requires using it from at least one doc in the same change, or the verify will fail.
- **Adding a new integ test file** alone does NOT invalidate the marker (only SKILL.md / README.md / scripts/integ.sh do, per `.markgate.yml` scope). New tests typically come with README changes anyway, which trip the marker naturally.
