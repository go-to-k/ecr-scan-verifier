---
name: integ-test
description: Orchestrate ecr-scan-verifier integ tests against real AWS. Handles Inspector enable/disable + propagation waits, scan-on-push toggling, image signing (Notation / Cosign KMS / Cosign Public Key / ECR Managed Signing), and cleanup. Use whenever the user wants to run anything under `test/integ/`.
argument-hint: "<status|basic|enhanced|signature-notation|signature-cosign-kms|signature-cosign-publickey|signature-ecr-signing|cleanup-signature> [--update] [--no-restore]"
---

# integ-test

End-to-end orchestrator for `test/integ/` tests. Replaces the manual checklist in `test/integ/README.md`.

The integ suite is split by required AWS account state:

| Directory       | Regions exercised             | Required state                                              |
| --------------- | ----------------------------- | ----------------------------------------------------------- |
| `basic/`        | `us-east-1 us-east-2 us-west-2` | Enhanced scanning (Inspector) **DISABLED** in all regions   |
| `enhanced/`     | `us-east-1 us-east-2 us-west-2` | Enhanced scanning (Inspector) **ENABLED** in all regions    |
| `signature/`    | default region only           | Pre-signed images + SSM/KMS prerequisites (state-agnostic)  |

When toggling Inspector for `basic`/`enhanced`, always operate on **all three** regions. Signature modes are single-region (resolved from `aws configure get region`).

## Arguments

- `status` — only triage current AWS state, propose no changes
- `basic` — switch state if needed, run `pnpm integ:basic`, restore
- `enhanced` — switch state if needed, run `pnpm integ:enhanced`, restore
- `signature-notation` — Notation (AWS Signer) sign + run `integ.notation`
- `signature-cosign-kms` — Cosign with KMS sign + run `integ.cosign-kms`
- `signature-cosign-publickey` — Cosign keypair sign + run `integ.cosign-publickey`
- `signature-ecr-signing` — ECR Managed Signing setup + run `integ.ecr-signing`
- `cleanup-signature` — Delete SSM params, schedule KMS key deletion, remove local key files

Flags:

- `--update` — pass `--update-on-failed` to `integ-runner` (use during real deploy to refresh snapshots)
- `--no-restore` — skip restoring Inspector state at the end (useful when running multiple modes back-to-back)

If no argument is given, use `AskUserQuestion` to ask which mode to run.

## Snapshot vs `--update` (read this first)

`pnpm integ:*` runs **snapshot tests only** — no AWS calls, no deploy. `pnpm integ:*:update` (or `pnpm integ:* --update-on-failed` via the `--update` flag) actually deploys to AWS.

This drastically changes what the skill needs to do:

| Without `--update` (snapshot)               | With `--update` (real deploy)                              |
| ------------------------------------------- | ---------------------------------------------------------- |
| Skip Inspector toggle entirely              | Toggle Inspector + poll convergence in all regions         |
| Skip scan-on-push toggle                    | Toggle scan-on-push on/off around the `basic` run           |
| Skip image signing setup                    | Run the full sign flow for signature modes                 |
| Just run `pnpm integ:<mode>`                | Run `pnpm integ:<mode>:update`                              |

**Rule of thumb**: if `--update` is not in the invocation, all AWS-state manipulation in this document is a no-op. Only the test runner command itself matters. The rest of this document describes the `--update` path; gate every AWS-mutating step on the flag.

## Common preamble (always run first)

1. Resolve once: `ACCOUNT=$(aws sts get-caller-identity --query Account --output text)`. Reuse for the rest of the run.
2. Capture the current Inspector state in **all three regions** so the restore step can put things back (only matters when `--update`, but cheap enough to always run for the `status` summary):

   ```bash
   for region in us-east-1 us-east-2 us-west-2; do
     echo "$region: $(aws inspector2 batch-get-account-status \
       --region "$region" \
       --query 'accounts[0].resourceState.ecr.status' \
       --output text)"
   done
   ```

   Record the result as `ORIGINAL_STATE` (`ENABLED` / `DISABLED`). If states differ between regions, surface it — that is itself a bug worth flagging before running tests.

3. Build Lambda once (only required for `--update` runs; `pnpm integ:*` snapshot variants chain this themselves, but doing it once up-front avoids repeating across mode dispatches):

   ```bash
   pnpm tsc -p tsconfig.dev.json
   (cd assets/lambda && pnpm install --frozen-lockfile && pnpm build)
   ```

## Polling helper (use everywhere a status change is awaited)

Never use a bare `sleep` or an unbounded `while`. The pattern below caps at 20 iterations × 15s = 5 minutes per region and fails loudly:

```bash
wait_inspector_status() {
  local region="$1" target="$2" i=0
  while [ "$(aws inspector2 batch-get-account-status --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' --output text)" != "$target" ]; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
      echo "ERROR: $region did not reach $target after 5 min" >&2
      return 1
    fi
    sleep 15
  done
}
```

Call as `wait_inspector_status us-east-1 DISABLED` etc. If it returns non-zero, abort the run and report — do not proceed to the test runner.

## Mode: `status`

Run the preamble step 2 only. Report per-region Inspector state and recommend which directories are ready to run:

- All ENABLED → `enhanced/` is ready. `basic/` requires a disable cycle.
- All DISABLED → `basic/` is ready. `enhanced/` requires an enable cycle.
- Mixed → flag as anomaly; ask the user before proceeding.

Exit without changing any state.

## Mode: `basic`

### Without `--update` (snapshot)

```bash
pnpm integ:basic
```

That's it. No Inspector toggle, no scan-on-push toggle, no restore. Skip the rest of this section.

### With `--update`

Requires Inspector **DISABLED** in all regions. `pnpm integ:basic:update` runs **all** basic tests including `integ.scan-on-push`, so scan-on-push must be enabled on the bootstrap repo **before** the run (not after a failure).

```bash
# 1. If ORIGINAL_STATE was ENABLED, disable Inspector in all regions
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 disable --resource-types ECR --region "$region"
done

# 2. Poll until DISABLED in all three regions
for region in us-east-1 us-east-2 us-west-2; do
  wait_inspector_status "$region" DISABLED || exit 1
done

# 3. Enable scan-on-push on the bootstrap asset repo in all three regions
#    (required by integ.scan-on-push, which is part of the basic suite)
for region in us-east-1 us-east-2 us-west-2; do
  REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${region}"
  aws ecr put-image-scanning-configuration \
    --repository-name "$REPO" \
    --image-scanning-configuration scanOnPush=true \
    --region "$region"
done

# 4. Run
pnpm integ:basic:update

# 5. Always restore scan-on-push to false, even if step 4 failed
for region in us-east-1 us-east-2 us-west-2; do
  REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${region}"
  aws ecr put-image-scanning-configuration \
    --repository-name "$REPO" \
    --image-scanning-configuration scanOnPush=false \
    --region "$region"
done
```

### Restore Inspector (unless `--no-restore`)

If `ORIGINAL_STATE` was `ENABLED`, re-enable Inspector in all regions and poll until ENABLED. If it was `DISABLED`, do nothing.

```bash
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 enable --resource-types ECR --region "$region"
done
for region in us-east-1 us-east-2 us-west-2; do
  wait_inspector_status "$region" ENABLED || exit 1
done
```

## Mode: `enhanced`

### Without `--update` (snapshot)

```bash
pnpm integ:enhanced
```

No AWS work needed.

### With `--update`

Requires Inspector **ENABLED** in all regions.

```bash
# 1. If ORIGINAL_STATE was DISABLED, enable in all regions
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 enable --resource-types ECR --region "$region"
done

# 2. Poll until ENABLED in all three
for region in us-east-1 us-east-2 us-west-2; do
  wait_inspector_status "$region" ENABLED || exit 1
done

# 3. If we just transitioned DISABLED→ENABLED, wait for the scanning engine
#    to catch up. `batch-get-account-status` flipping to ENABLED is NOT the
#    same as the engine being ready — newly pushed images can produce empty
#    findings for 10+ minutes after the API flip. Skip this wait when
#    ORIGINAL_STATE was already ENABLED (no transition happened).
if [ "$ORIGINAL_STATE" = "DISABLED" ]; then
  echo "Waiting 10 minutes for Inspector scanning engine to warm up..."
  sleep 600
fi

# 4. Run, with one automatic retry on the engine-warmup failure mode.
#    A "real" failure (vulnerability findings, code bugs) will surface the
#    same way on retry — we only want to absorb the empty-findings-during-
#    warmup case. Cap at ONE retry to keep total time bounded.
if ! pnpm integ:enhanced:update; then
  echo "First attempt failed. Waiting 5 more minutes and retrying once..."
  sleep 300
  pnpm integ:enhanced:update || {
    echo "ERROR: enhanced/ tests failed twice. Investigate findings rather than waiting longer." >&2
    exit 1
  }
fi
```

**Critical wait**: This wait + single-retry pattern exists because the Inspector scanning engine lags the `batch-get-account-status` ENABLED flip by 10+ minutes on a fresh enable. **Do not extend the retry count beyond 1** — if two attempts spanning ~15 minutes both fail, the cause is not propagation lag and waiting longer only burns time. Diagnose the failure (findings? IAM? region? construct bug?) instead.

### Restore (unless `--no-restore`)

If `ORIGINAL_STATE` was `DISABLED`, disable in all regions and poll until DISABLED. If it was `ENABLED`, do nothing.

## Signature modes — shared preamble

All four signature modes share these steps. Run them at the start of every signature-mode invocation (only when `--update`; without `--update` just run the snapshot variant).

```bash
# Clear cdk.out/ so prior signature runs do not leak stale assets manifests
rm -rf cdk.out/

REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
```

`signature-ecr-signing` uses its own dedicated repo (not the bootstrap one) — see that section.

## Mode: `signature-notation`

### Without `--update` (snapshot)

```bash
pnpm integ:signature --language javascript --test-regex "integ.notation.js$"
```

### With `--update`

Notation (AWS Signer) signs an OCI-stored asset and the integ test verifies it.

**Profile reuse**: AWS Signer profiles cannot be deleted (only canceled), and a canceled profile cannot be reused for signing. We intentionally keep `EcrScanVerifierTestProfile` `Active` across runs (`put-signing-profile` is idempotent on Active profiles). If you find it `Canceled`, use a new name (e.g. `EcrScanVerifierTestProfile2`) and substitute throughout.

Pre-flight: `notation version` should succeed. If absent, install via the AWS Signer installer pkg (see `test/integ/README.md` → Notation install — do not improvise URLs).

```bash
# (Assumes shared preamble has run: cdk.out/ cleared, REGION/REGISTRY/REPO set)

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

# 5. Run the integ test
pnpm integ:signature:update --language javascript --test-regex "integ.notation.js$"
```

**Immutable-tag recovery**: If `notation sign` fails with `tag invalid: ... already exists ... cannot be overwritten because the tag is immutable`, a previous attempt left a partial referrers index tag. The bootstrap repo uses immutable tags, so the leftover must be deleted before retrying:

```bash
REFERRER_TAG="sha256-${DIGEST#sha256:}"
aws ecr batch-delete-image --repository-name "${REPO}" \
  --image-ids imageTag="${REFERRER_TAG}"
```

Then retry the `notation sign` step.

## Mode: `signature-cosign-kms`

### Without `--update` (snapshot)

```bash
pnpm integ:signature --language javascript --test-regex "integ.cosign-kms.js$"
```

### With `--update`

**Rekor note**: the Lambda verifier always skips Rekor transparency log. Sign with the same skip so the test matches Lambda behavior — verification then works offline / inside VPC without internet.

```bash
# (Assumes shared preamble has run: cdk.out/ cleared, REGION/REGISTRY/REPO set)

# 1. Tools
command -v cosign >/dev/null || brew install cosign

# 2. Create KMS key + persist its id in SSM (the construct reads from SSM)
KMS_KEY_ID=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --query 'KeyMetadata.KeyId' --output text)
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-kms-key-id \
  --value "${KMS_KEY_ID}" --type String --overwrite
KMS_KEY_ARN=$(aws kms describe-key --key-id "${KMS_KEY_ID}" \
  --query 'KeyMetadata.Arn' --output text)

# 3. Synth + publish the asset
npx cdk synth --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish

# 4. Resolve digest of the test fixture
ASSET_HASH=$(cat cdk.out/CosignKmsSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

# 5. Sign WITHOUT Rekor (matches Lambda verifier)
aws ecr get-login-password --region "${REGION}" | cosign login --username AWS --password-stdin "${REGISTRY}"
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json
cosign sign --signing-config /tmp/signing-config.json \
  --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

# 6. Run
pnpm integ:signature:update --language javascript --test-regex "integ.cosign-kms.js$"
```

## Mode: `signature-cosign-publickey`

### Without `--update` (snapshot)

```bash
pnpm integ:signature --language javascript --test-regex "integ.cosign-publickey.js$"
```

### With `--update`

Same Rekor-skip rule as `signature-cosign-kms`.

```bash
# (Assumes shared preamble has run: cdk.out/ cleared, REGION/REGISTRY/REPO set)

# 1. Tools
command -v cosign >/dev/null || brew install cosign

# 2. Generate a keypair non-interactively. COSIGN_PASSWORD="" disables the
#    blocking password prompt — required when the skill runs unattended.
COSIGN_PASSWORD="" cosign generate-key-pair
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-public-key \
  --value "$(cat cosign.pub)" --type String --overwrite

# 3. Synth + publish the asset
npx cdk synth --app 'node test/integ/signature/integ.cosign-publickey.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignPublicKeySignatureStack.assets.json publish

# 4. Resolve digest of the test fixture
ASSET_HASH=$(cat cdk.out/CosignPublicKeySignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

# 5. Sign WITHOUT Rekor (matches Lambda verifier). COSIGN_PASSWORD="" again
#    to unlock the local private key without prompting.
aws ecr get-login-password --region "${REGION}" | cosign login --username AWS --password-stdin "${REGISTRY}"
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json
COSIGN_PASSWORD="" cosign sign --signing-config /tmp/signing-config.json \
  --key cosign.key "${REGISTRY}/${REPO}@${DIGEST}"

# 6. Run
pnpm integ:signature:update --language javascript --test-regex "integ.cosign-publickey.js$"
```

`cosign.key` / `cosign.pub` are git-ignored. Do NOT commit them, and remove them in `cleanup-signature`.

## Mode: `signature-ecr-signing`

### Without `--update` (snapshot)

```bash
pnpm integ:signature --language javascript --test-regex "integ.ecr-signing.js$"
```

### With `--update`

ECR Managed Signing auto-signs on push when a signing-configuration matches the repository. The integ uses `ECRDeployment` to copy a CDK asset into a signing-enabled repo so that the push triggers a signature.

**Regional gotcha**: `aws ecr put-signing-configuration` is not available in every region. If the API call returns `UnknownOperationException` or similar, abort and report the region — do not silently fall back.

**Permissions gotcha**: the caller needs `signer:*` including `signer:SignPayload`. Surface a friendly error if `put-signing-configuration` fails on `AccessDenied`.

```bash
# (Assumes shared preamble has run: cdk.out/ cleared, REGION set)

# 1. Profile (reused with signature-notation)
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTestProfile \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Create a dedicated repo (not the CDK bootstrap one)
REPO_NAME="ecr-scan-verifier-integ-ecr-signing"
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTestProfile --query 'arn' --output text)
aws ecr create-repository --repository-name "${REPO_NAME}" 2>/dev/null || true

# 3. Enable signing-configuration scoped to that repo
cat > /tmp/signing-config.json <<EOF
{
  "rules": [
    {
      "signingProfileArn": "${PROFILE_ARN}",
      "repositoryFilters": [
        { "filter": "${REPO_NAME}", "filterType": "WILDCARD_MATCH" }
      ]
    }
  ]
}
EOF
aws ecr put-signing-configuration --region "${REGION}" \
  --signing-configuration file:///tmp/signing-config.json
aws ecr get-signing-configuration --region "${REGION}"  # verify

# 4. Run
pnpm integ:signature:update --language javascript --test-regex "integ.ecr-signing.js$"

# 5. Cleanup specific to this mode — ALWAYS run, even if step 4 failed.
#    Use a trap or guarantee cleanup in the orchestration; do not let a
#    failed test leave the signing-configuration / repo behind.
cat > /tmp/signing-config-empty.json <<EOF
{ "rules": [] }
EOF
aws ecr put-signing-configuration --region "${REGION}" \
  --signing-configuration file:///tmp/signing-config-empty.json
aws ecr delete-repository --repository-name "${REPO_NAME}" --force
```

## Mode: `cleanup-signature`

Removes shared signature-test artifacts. Run after you're done with all signature modes for the day. **AWS Signer profiles are not deleted here** (cancellation is permanent and would break future runs).

```bash
# 1. Resolve KMS key id from SSM BEFORE deleting the param
KMS_KEY_ID=$(aws ssm get-parameter --name /ecr-scan-verifier/cosign-kms-key-id \
  --query 'Parameter.Value' --output text 2>/dev/null || true)

# 2. SSM params (cosign)
aws ssm delete-parameter --name /ecr-scan-verifier/cosign-kms-key-id 2>/dev/null || true
aws ssm delete-parameter --name /ecr-scan-verifier/cosign-public-key 2>/dev/null || true

# 3. KMS: schedule deletion (minimum 7 days). If SSM is already gone and the
#    id wasn't recovered above, ASK the user for the key id rather than
#    guessing — KMS deletion is non-trivial to reverse.
if [ -n "$KMS_KEY_ID" ]; then
  aws kms schedule-key-deletion --key-id "$KMS_KEY_ID" --pending-window-in-days 7
else
  echo "WARN: KMS key id not in SSM. Ask the user before scheduling deletion." >&2
fi

# 4. Local cosign keypair
rm -f cosign.key cosign.pub
```

## Reporting

At the end of every run, print:

- Mode invoked + whether `--update` was set + duration
- `ORIGINAL_STATE` and whether it was restored (or "n/a" for snapshot-only)
- Test pass/fail counts (parse from `integ-runner` output)
- Any leftover side effects (e.g. `EcrScanVerifierTestProfile` left Active intentionally; signing-configuration disabled; `cosign.key` removed; etc.)

Never end with stale state silently. If a restore step was skipped or failed, say so explicitly.

## Important

- **Snapshot runs do not touch AWS.** Gate every AWS-mutating step on `--update`. Running the Inspector toggle for a snapshot-only run is wasted effort and can paradoxically break other concurrent work.
- **Always operate on all three regions** (`us-east-1 us-east-2 us-west-2`) when toggling Inspector — partial toggles cause hard-to-debug test failures.
- **Poll with a bounded loop** (see `wait_inspector_status`) — never use a bare `sleep` or unbounded `while`. Inspector propagation is variable but capping at 5 min per region surfaces stuck transitions instead of hanging.
- **`enhanced` engine lag — wait then retry once**: status flipping to `ENABLED` is not the same as the scanning engine being ready. On a fresh DISABLED→ENABLED transition, sleep 600s before the first test attempt, and on first-attempt failure sleep another 300s and retry exactly once. Do not extend beyond one retry — if both ~15-minute attempts fail, the cause is not propagation lag and waiting longer is a waste.
- **Always enable scan-on-push proactively for `basic --update`** — `pnpm integ:basic:update` runs the `integ.scan-on-push` test in the same suite, so toggling on after a failure is too late.
- **Never cancel `EcrScanVerifierTestProfile`** — cancellation is permanent and blocks future runs under the same name.
- **`cosign generate-key-pair` and `cosign sign` need `COSIGN_PASSWORD=""`** when run unattended — otherwise they hang on a password prompt.
- **Never commit `cosign.key` / `cosign.pub`** — they're git-ignored, keep it that way.
- **Bootstrap repo uses immutable tags** — leftover Notation referrer tags from a failed `notation sign` MUST be deleted before retrying; do not work around with a fresh tag.
- **`signature-ecr-signing` cleanup is not optional** — the signing-configuration and dedicated repo must be torn down even if the test fails, otherwise the next run starts in a dirty state.
- When in doubt about which test to run, call `AskUserQuestion` rather than guess.
