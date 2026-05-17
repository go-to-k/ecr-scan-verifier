---
name: integ-test
description: Orchestrate ecr-scan-verifier integ tests against real AWS. Handles Inspector enable/disable + propagation waits, scan-on-push toggling, image signing (Notation / Cosign KMS / Cosign Public Key / ECR Managed Signing), and cleanup. Use whenever the user wants to run anything under `test/integ/`.
argument-hint: "<status|basic|enhanced|signature|signature-notation|signature-cosign-kms|signature-cosign-publickey|signature-ecr-signing|all|cleanup-signature> [--snapshot-only] [--no-restore]"
---

# integ-test

End-to-end orchestrator for `test/integ/` tests. Replaces the manual checklist in `test/integ/README.md`.

Most AWS-mutating primitives live in [`scripts/integ.sh`](../../../scripts/integ.sh) as shell functions. This skill **always sources that file first** and composes the functions per mode — keep primitives there, keep orchestration here.

```bash
. scripts/integ.sh
```

After sourcing you have: `account_id`, `default_region`, `inspector_status`, `inspector_status_all`, `inspector_enable_all`, `inspector_disable_all`, `wait_inspector_status`, `wait_inspector_status_all`, `scan_on_push_set`, `wait_enhanced_engine_warmup`, `enhanced_run_with_retry`, `cleanup_signature_artifacts`, `ecr_signing_setup`, `ecr_signing_teardown`.

## Integ suite layout

| Directory   | Regions exercised               | Required state                                              |
| ----------- | ------------------------------- | ----------------------------------------------------------- |
| `basic/`    | `us-east-1 us-east-2 us-west-2` | Enhanced scanning (Inspector) **DISABLED** in all regions   |
| `enhanced/` | `us-east-1 us-east-2 us-west-2` | Enhanced scanning (Inspector) **ENABLED** in all regions    |
| `signature/`| default region only             | Pre-signed images + SSM/KMS prerequisites (state-agnostic)  |

Signature modes are single-region (resolved from `aws configure get region`). `basic`/`enhanced` always operate on **all three** regions.

## Default behavior: real deploy

The skill **deploys to AWS by default**. The `pnpm integ:*` scripts wrap `integ-runner`; without `--update-on-failed`, integ-runner does a *snapshot template comparison only* and never touches AWS. With `--update-on-failed` (which the skill passes by default), it actually deploys.

If you only want the cheap snapshot comparison, pass `--snapshot-only`. The skill then degenerates to a single `pnpm integ:<mode>` call and **skips every AWS-mutating step** (Inspector toggle, scan-on-push toggle, signing setup).

## Arguments

- `status` — only triage current AWS state, propose no changes
- `basic` — switch Inspector if needed, run `pnpm integ:basic:update`, restore
- `enhanced` — switch Inspector if needed, warm engine, run `pnpm integ:enhanced:update`, restore
- `signature` — run all four signature sub-modes back-to-back
- `signature-notation` — Notation (AWS Signer) sign + run `integ.notation`
- `signature-cosign-kms` — Cosign with KMS sign + run `integ.cosign-kms`
- `signature-cosign-publickey` — Cosign keypair sign + run `integ.cosign-publickey`
- `signature-ecr-signing` — ECR Managed Signing setup + run `integ.ecr-signing`
- `all` — run **everything** (enhanced → all signatures → basic), then auto-run `cleanup-signature`
- `cleanup-signature` — delete SSM params, schedule KMS key deletion, remove local key files

Flags:

- `--snapshot-only` — skip every AWS-mutating step; just run `pnpm integ:<mode>` (template comparison only). Mutually exclusive with the orchestration in each mode below.
- `--no-restore` — skip restoring Inspector state at the end (useful when running multiple modes back-to-back). **Ignored by `all`**, which always restores.

### When invoked without arguments

Use `AskUserQuestion` to elicit BOTH the mode and the snapshot flag:

1. **Target**:
   - `basic`
   - `enhanced`
   - `signature` (all four signature sub-modes)
   - `all` (everything end-to-end with auto-cleanup)
   - `status` (just triage, no test run)
2. **Run mode**:
   - **Deploy** (default) — real AWS deploy, refresh snapshots
   - **Snapshot-only** — template comparison only, no AWS calls

Skip both prompts if the user already gave the target. If they gave the target but not the run-mode, only ask the second question.

## `--snapshot-only` (any mode)

Single command, no helpers, no setup. The skill exits after this:

```bash
pnpm integ            # all directories
pnpm integ:basic      # or one directory
pnpm integ:enhanced
pnpm integ:signature
```

For per-test signature snapshots:

```bash
pnpm integ:signature --language javascript --test-regex "integ.notation.js$"
```

Nothing else in this document applies when `--snapshot-only` is set.

## Post-run cleanup (deploy runs only)

After ANY deploy-mode invocation (single mode or `all`), the skill must:

1. Confirm Inspector state has been restored as documented in the mode (or, with `--no-restore`, explicitly report what was left as-is).
2. For `all` and any `signature-*` deploy run, finish with `cleanup_signature_artifacts` from `scripts/integ.sh`. Single `signature-*` runs leave SSM/KMS in place by default so the user can chain modes — call cleanup at the very end of the session.
3. Print the full reporting summary (see [Reporting](#reporting)) — never end silently.

## Common preamble (deploy runs)

```bash
. scripts/integ.sh
ACCOUNT="$(account_id)"
ORIGINAL_STATE_EAST1="$(inspector_status us-east-1)"
ORIGINAL_STATE_EAST2="$(inspector_status us-east-2)"
ORIGINAL_STATE_WEST2="$(inspector_status us-west-2)"
```

If the three states differ, surface it — that itself is worth flagging before running anything.

Build the Lambda once up front (every `pnpm integ:*` script chains this, but doing it once avoids repeating across modes):

```bash
pnpm tsc -p tsconfig.dev.json
(cd assets/lambda && pnpm install --frozen-lockfile && pnpm build)
```

## Mode: `status`

```bash
inspector_status_all
```

Then recommend:

- All ENABLED → `enhanced/` is ready. `basic/` requires a disable cycle.
- All DISABLED → `basic/` is ready. `enhanced/` requires an enable cycle.
- Mixed → flag as anomaly; ask before proceeding.

Exit without changing any state.

## Mode: `basic` (deploy)

`pnpm integ:basic:update` runs **all** basic tests including `integ.scan-on-push`, so scan-on-push must be on **before** the run.

```bash
inspector_disable_all
wait_inspector_status_all DISABLED || exit 1
scan_on_push_set true

# Run, then ALWAYS restore scan-on-push (use a trap or explicit if/then)
if pnpm integ:basic:update; then status=0; else status=$?; fi
scan_on_push_set false
[ "$status" -eq 0 ] || exit "$status"
```

### Restore Inspector (unless `--no-restore`)

If any region's `ORIGINAL_STATE_*` was `ENABLED`, restore that region. Simplest correct approach when all three were originally identical: re-enable everywhere if any was originally ENABLED.

```bash
if [ "$ORIGINAL_STATE_EAST1" = "ENABLED" ] || \
   [ "$ORIGINAL_STATE_EAST2" = "ENABLED" ] || \
   [ "$ORIGINAL_STATE_WEST2" = "ENABLED" ]; then
  inspector_enable_all
  wait_inspector_status_all ENABLED || exit 1
fi
```

## Mode: `enhanced` (deploy)

```bash
# Capture the "was DISABLED in any region" condition BEFORE we flip,
# because wait_enhanced_engine_warmup needs to know whether a real
# transition is happening (the engine only lags on fresh enable).
TRANSITION="ENABLED"
if [ "$ORIGINAL_STATE_EAST1" != "ENABLED" ] || \
   [ "$ORIGINAL_STATE_EAST2" != "ENABLED" ] || \
   [ "$ORIGINAL_STATE_WEST2" != "ENABLED" ]; then
  TRANSITION="DISABLED"
fi

inspector_enable_all
wait_inspector_status_all ENABLED || exit 1

# Engine warmup: empirically 20-30 min on a fresh enable.
wait_enhanced_engine_warmup "$TRANSITION" 1200

# Up to 3 attempts × 10 min gap. Calibrated to the warmup tail —
# NOT to flaky tests. If 3 fail, stop.
MAX_ATTEMPTS=3 RETRY_GAP_SECS=600 \
  enhanced_run_with_retry pnpm integ:enhanced:update || exit 1
```

### Restore (unless `--no-restore`)

If all three `ORIGINAL_STATE_*` were `DISABLED`, disable in all regions and poll until DISABLED. Otherwise leave as-is.

## Signature modes — shared preamble (deploy)

```bash
rm -rf cdk.out/    # avoid stale assets manifests from prior signature runs
REGION="$(default_region)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
```

`signature-ecr-signing` uses its own dedicated repo (set up via `ecr_signing_setup`).

## Mode: `signature-notation` (deploy)

**Profile reuse**: AWS Signer profiles cannot be deleted (only canceled), and a canceled profile cannot be reused. We intentionally keep `EcrScanVerifierTestProfile` `Active` across runs (`put-signing-profile` is idempotent on Active profiles). If you find it `Canceled`, use a new name (e.g. `EcrScanVerifierTestProfile2`) and substitute throughout.

Pre-flight: `notation version` should succeed. If absent, install via the AWS Signer installer pkg (see `test/integ/README.md` → Notation install — do not improvise URLs).

```bash
# 1. Idempotent profile create
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTestProfile \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Synth + publish only the Docker asset (no stack deploy yet)
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTestProfile --query 'arn' --output text)
npx cdk synth --app 'node test/integ/signature/integ.notation.js' -o cdk.out
npx cdk-assets -p cdk.out/NotationSignatureStack.assets.json publish

# 3. Resolve the test fixture digest (NOT the Lambda function image)
ASSET_HASH=$(cat cdk.out/NotationSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

# 4. Sign
aws ecr get-login-password | notation login --username AWS --password-stdin "${REGISTRY}"
notation sign \
  --plugin com.amazonaws.signer.notation.plugin \
  --id "${PROFILE_ARN}" \
  "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run
pnpm integ:signature:update --language javascript --test-regex "integ.notation.js$"
```

**Immutable-tag recovery**: If `notation sign` fails with `tag invalid: ... already exists ... cannot be overwritten because the tag is immutable`, a previous attempt left a partial referrers index tag. The bootstrap repo uses immutable tags, so the leftover must be deleted before retrying:

```bash
REFERRER_TAG="sha256-${DIGEST#sha256:}"
aws ecr batch-delete-image --repository-name "${REPO}" \
  --image-ids imageTag="${REFERRER_TAG}"
```

Then retry the `notation sign` step.

## Mode: `signature-cosign-kms` (deploy)

**Rekor note**: the Lambda verifier always skips Rekor. Sign with the same skip so the test matches Lambda behavior — verification then works offline / inside VPC without internet.

```bash
command -v cosign >/dev/null || brew install cosign

KMS_KEY_ID=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --query 'KeyMetadata.KeyId' --output text)
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-kms-key-id \
  --value "${KMS_KEY_ID}" --type String --overwrite
KMS_KEY_ARN=$(aws kms describe-key --key-id "${KMS_KEY_ID}" \
  --query 'KeyMetadata.Arn' --output text)

npx cdk synth --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish

ASSET_HASH=$(cat cdk.out/CosignKmsSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password --region "${REGION}" | cosign login --username AWS --password-stdin "${REGISTRY}"
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json
cosign sign --signing-config /tmp/signing-config.json \
  --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

pnpm integ:signature:update --language javascript --test-regex "integ.cosign-kms.js$"
```

## Mode: `signature-cosign-publickey` (deploy)

Same Rekor-skip rule. `COSIGN_PASSWORD=""` required on `generate-key-pair` and `sign` to avoid the interactive password prompt blocking unattended runs.

```bash
command -v cosign >/dev/null || brew install cosign

COSIGN_PASSWORD="" cosign generate-key-pair
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-public-key \
  --value "$(cat cosign.pub)" --type String --overwrite

npx cdk synth --app 'node test/integ/signature/integ.cosign-publickey.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignPublicKeySignatureStack.assets.json publish

ASSET_HASH=$(cat cdk.out/CosignPublicKeySignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password --region "${REGION}" | cosign login --username AWS --password-stdin "${REGISTRY}"
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json
COSIGN_PASSWORD="" cosign sign --signing-config /tmp/signing-config.json \
  --key cosign.key "${REGISTRY}/${REPO}@${DIGEST}"

pnpm integ:signature:update --language javascript --test-regex "integ.cosign-publickey.js$"
```

`cosign.key` / `cosign.pub` are git-ignored. Do NOT commit them, and remove them via `cleanup-signature`.

## Mode: `signature-ecr-signing` (deploy)

ECR Managed Signing auto-signs on push when a signing-configuration matches the repository. The integ uses `ECRDeployment` to copy a CDK asset into a signing-enabled repo so that the push triggers a signature.

**Regional gotcha**: `aws ecr put-signing-configuration` is not available in every region. If the API call returns `UnknownOperationException` or similar, abort and report — do not silently fall back.

**Permissions gotcha**: the caller needs `signer:*` including `signer:SignPayload`. Surface a friendly error on `AccessDenied`.

```bash
ecr_signing_setup

if pnpm integ:signature:update --language javascript --test-regex "integ.ecr-signing.js$"; then
  status=0
else
  status=$?
fi
ecr_signing_teardown
exit "$status"
```

## Mode: `signature` (deploy)

Runs all four signature sub-modes back-to-back. They are state-agnostic w.r.t. Inspector, but each mutates SSM/KMS/ECR and synths into the shared `cdk.out/`, so order matters.

Failures in earlier modes do NOT short-circuit later ones — capture per-mode status and surface them all in the final report. Each mode's preamble (`rm -rf cdk.out/`, REGION/REGISTRY/REPO export) must run anew per iteration.

```bash
sig_status=()
for mode in signature-notation signature-cosign-kms signature-cosign-publickey signature-ecr-signing; do
  echo "=== Running mode: $mode ==="
  if run_mode "$mode"; then
    sig_status+=("$mode: PASS")
  else
    sig_status+=("$mode: FAIL")
  fi
done
printf '%s\n' "${sig_status[@]}"
```

After the loop, finish with `cleanup_signature_artifacts`.

## Mode: `all` (deploy)

Runs **every** integ test end-to-end with optimal Inspector state transitions.

State-transition strategy (minimizes Inspector flips, which each cost a ~5 min poll + the ~20 min engine warmup on enable):

1. **Enable Inspector** (if not already) and absorb the engine warmup. Serves both `enhanced` AND positions us for `signature-*` (state-agnostic but cheaper to keep ENABLED across them).
2. **Run `enhanced`** with the 3-attempt retry loop.
3. **Run all four `signature-*` modes**.
4. **Flip Inspector to DISABLED** + poll.
5. **Run `basic`** (proactive scan-on-push enable + unconditional restore).
6. **Restore Inspector to `ORIGINAL_STATE_*`** — `all` IGNORES `--no-restore` because a both-directions sequence has no obvious "as-found" target.
7. **Run `cleanup_signature_artifacts`** unconditionally.

Pseudocode:

```bash
. scripts/integ.sh
ACCOUNT="$(account_id)"
ORIGINAL_STATE_EAST1="$(inspector_status us-east-1)"
ORIGINAL_STATE_EAST2="$(inspector_status us-east-2)"
ORIGINAL_STATE_WEST2="$(inspector_status us-west-2)"

pnpm tsc -p tsconfig.dev.json
(cd assets/lambda && pnpm install --frozen-lockfile && pnpm build)

# --- 1+2: enhanced ---
TRANSITION="ENABLED"
if [ "$ORIGINAL_STATE_EAST1" != "ENABLED" ] || \
   [ "$ORIGINAL_STATE_EAST2" != "ENABLED" ] || \
   [ "$ORIGINAL_STATE_WEST2" != "ENABLED" ]; then
  TRANSITION="DISABLED"
fi
inspector_enable_all
wait_inspector_status_all ENABLED || exit 1
wait_enhanced_engine_warmup "$TRANSITION" 1200

results=()
if MAX_ATTEMPTS=3 RETRY_GAP_SECS=600 \
   enhanced_run_with_retry pnpm integ:enhanced:update; then
  results+=("enhanced: PASS")
else
  results+=("enhanced: FAIL")
fi

# --- 3: all signatures ---
for mode in signature-notation signature-cosign-kms signature-cosign-publickey signature-ecr-signing; do
  if run_signature_mode "$mode"; then
    results+=("$mode: PASS")
  else
    results+=("$mode: FAIL")
  fi
done

# --- 4+5: basic ---
inspector_disable_all
wait_inspector_status_all DISABLED || exit 1
scan_on_push_set true
if pnpm integ:basic:update; then
  results+=("basic: PASS")
else
  results+=("basic: FAIL")
fi
scan_on_push_set false

# --- 6: restore Inspector (always for `all`) ---
if [ "$ORIGINAL_STATE_EAST1" = "ENABLED" ] || \
   [ "$ORIGINAL_STATE_EAST2" = "ENABLED" ] || \
   [ "$ORIGINAL_STATE_WEST2" = "ENABLED" ]; then
  inspector_enable_all
  wait_inspector_status_all ENABLED || exit 1
fi

# --- 7: cleanup ---
cleanup_signature_artifacts

printf '%s\n' "${results[@]}"
```

Wall-clock budget for a clean `all` run: roughly 45–80 minutes depending on Inspector warmup and signature retries. Plan accordingly.

## Mode: `cleanup-signature`

```bash
cleanup_signature_artifacts
```

The function resolves the KMS key id from SSM before deleting the param. If SSM is already gone and the id can't be recovered, it prints a WARN and skips KMS deletion — ask the user for the key id rather than guess.

## Reporting

At the end of every run, print:

- Mode invoked + whether `--snapshot-only` was set + duration
- `ORIGINAL_STATE_*` per region and whether each was restored (or "n/a" for snapshot-only)
- Test pass/fail counts (parse from `integ-runner` output)
- Any leftover side effects (e.g. `EcrScanVerifierTestProfile` left Active intentionally; signing-configuration disabled; `cosign.key` removed)

Never end with stale state silently. If a restore step was skipped or failed, say so explicitly.

## Important

- **Deploy is the default.** Snapshot-only is opt-in via `--snapshot-only`, which collapses every mode to a single `pnpm integ:<mode>` call with no AWS calls and no state changes.
- **Always operate on all three regions** (`us-east-1 us-east-2 us-west-2`) when toggling Inspector — partial toggles cause hard-to-debug test failures.
- **Poll with a bounded loop** (`wait_inspector_status` from `scripts/integ.sh`) — never use a bare `sleep` for state convergence.
- **`enhanced` engine lag is long**: status flipping to `ENABLED` is not the same as the scanning engine being ready. On a fresh DISABLED→ENABLED transition, sleep 1200s (20 min) before the first test attempt, then allow up to 3 total attempts with 600s (10 min) gaps. This worst-case ~40 min budget matches observed warmup. If all 3 fail, the cause is not propagation lag — stop waiting and investigate.
- **Always enable scan-on-push proactively for `basic`** — `pnpm integ:basic:update` runs the `integ.scan-on-push` test in the same suite, so toggling on after a failure is too late.
- **Never cancel `EcrScanVerifierTestProfile`** — cancellation is permanent and blocks future runs under the same name.
- **`cosign generate-key-pair` and `cosign sign` need `COSIGN_PASSWORD=""`** when run unattended — otherwise they hang on a password prompt.
- **Never commit `cosign.key` / `cosign.pub`** — they're git-ignored, keep it that way.
- **Bootstrap repo uses immutable tags** — leftover Notation referrer tags from a failed `notation sign` MUST be deleted before retrying; do not work around with a fresh tag.
- **`signature-ecr-signing` teardown is not optional** — wrap the test runner so `ecr_signing_teardown` runs even on failure.
- When in doubt about which test to run, call `AskUserQuestion` rather than guess.
