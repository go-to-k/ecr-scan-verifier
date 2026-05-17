---
name: integ-test
description: Orchestrate ecr-scan-verifier integ tests against real AWS. Handles Inspector enable/disable + propagation waits, scan-on-push toggling, image signing (Notation / Cosign KMS / Cosign Public Key / ECR Managed Signing), and cleanup. Use whenever the user wants to run anything under `test/integ/`.
argument-hint: "<status|basic|enhanced|signature-notation|signature-cosign-kms|signature-cosign-publickey|signature-ecr-signing|cleanup-signature> [--update] [--no-restore]"
---

# integ-test

End-to-end orchestrator for `test/integ/` tests. Replaces the manual checklist in `test/integ/README.md`.

The integ suite is split by required AWS account state:

| Directory       | Required state                                              |
| --------------- | ----------------------------------------------------------- |
| `basic/`        | Enhanced scanning (Inspector) **DISABLED** in all regions   |
| `enhanced/`     | Enhanced scanning (Inspector) **ENABLED** in all regions    |
| `signature/`    | Pre-signed images + SSM/KMS prerequisites (state-agnostic)  |

Regions used by integ tests: `us-east-1 us-east-2 us-west-2` — always operate on **all three** when toggling Inspector.

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

## Common preamble (always run first)

1. Resolve once: `ACCOUNT=$(aws sts get-caller-identity --query Account --output text)`. Reuse for the rest of the run.
2. Capture the current Inspector state in **all three regions** so the restore step can put things back:

   ```bash
   for region in us-east-1 us-east-2 us-west-2; do
     echo "$region: $(aws inspector2 batch-get-account-status \
       --region "$region" \
       --query 'accounts[0].resourceState.ecr.status' \
       --output text)"
   done
   ```

   Record the result as `ORIGINAL_STATE` (`ENABLED` / `DISABLED`). If states differ between regions, surface it — that is itself a bug worth flagging before running tests.

3. Build Lambda once. Most `pnpm integ:*` scripts already chain this, but doing it once up-front avoids repeating it across mode dispatches:

   ```bash
   pnpm tsc -p tsconfig.dev.json
   (cd assets/lambda && pnpm install --frozen-lockfile && pnpm build)
   ```

## Mode: `status`

Run the preamble step 2 only. Report per-region Inspector state and recommend which directories are ready to run:

- All ENABLED → `enhanced/` is ready. `basic/` requires a disable cycle.
- All DISABLED → `basic/` is ready. `enhanced/` requires an enable cycle.
- Mixed → flag as anomaly; ask the user before proceeding.

Exit without changing any state.

## Mode: `basic`

Requires Inspector **DISABLED** in all regions.

```bash
# 1. If currently ENABLED, disable in all regions
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 disable --resource-types ECR --region "$region"
done

# 2. Poll until status is DISABLED in all three regions before running tests.
#    `disable` is async — do NOT proceed on the first DISABLED reading from
#    one region. Re-poll until ALL three report DISABLED.
```

Polling pattern (use a real loop, not a fixed sleep):

```bash
for region in us-east-1 us-east-2 us-west-2; do
  while [ "$(aws inspector2 batch-get-account-status --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' --output text)" != "DISABLED" ]; do
    sleep 15
  done
done
```

Then run:

```bash
pnpm integ:basic           # or: pnpm integ:basic:update with --update
```

### Sub-case: `integ.scan-on-push`

This single test inside `basic/` additionally requires scan-on-push enabled on the CDK bootstrap asset repository in all three regions. Detect by reading the test name from the failure output, or by user request. Toggle:

```bash
# Enable before deploying
for region in us-east-1 us-east-2 us-west-2; do
  REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${region}"
  aws ecr put-image-scanning-configuration \
    --repository-name "$REPO" \
    --image-scanning-configuration scanOnPush=true \
    --region "$region"
done

# Restore to false after
for region in us-east-1 us-east-2 us-west-2; do
  REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${region}"
  aws ecr put-image-scanning-configuration \
    --repository-name "$REPO" \
    --image-scanning-configuration scanOnPush=false \
    --region "$region"
done
```

### Restore (unless `--no-restore`)

If `ORIGINAL_STATE` was `ENABLED`, re-enable Inspector in all regions and poll until ENABLED. If it was `DISABLED`, do nothing.

## Mode: `enhanced`

Requires Inspector **ENABLED** in all regions.

```bash
# 1. If currently DISABLED, enable in all regions
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 enable --resource-types ECR --region "$region"
done

# 2. Poll until ENABLED in all three (same loop pattern as basic mode)
```

**Critical wait**: Even after `batch-get-account-status` reports `ENABLED`, the Inspector scanning engine may need **10+ minutes** before newly pushed images are actually scanned. If `enhanced/` tests fail with empty/missing findings on the first attempt after a state transition, do NOT immediately conclude failure — wait several more minutes and retry once before reporting.

Then run:

```bash
pnpm integ:enhanced        # or: pnpm integ:enhanced:update with --update
```

Restore symmetric to `basic` mode.

## Mode: `signature-notation`

Notation (AWS Signer) signs an OCI-stored asset and the integ test verifies it.

**Profile reuse**: AWS Signer profiles cannot be deleted (only canceled), and a canceled profile cannot be reused for signing. We intentionally keep `EcrScanVerifierTestProfile` `Active` across runs (`put-signing-profile` is idempotent on Active profiles). If you find it `Canceled`, use a new name (e.g. `EcrScanVerifierTestProfile2`) and substitute throughout.

Pre-flight: `notation version` should succeed. If absent, install via the AWS Signer installer pkg (see `test/integ/README.md` → Notation install — do not improvise URLs).

```bash
# 1. Idempotent profile create
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTestProfile \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Synth + publish only the Docker asset (no stack deploy yet)
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
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

**Rekor note**: the Lambda verifier always skips Rekor transparency log. Sign with the same skip so the test matches Lambda behavior — verification then works offline / inside VPC without internet.

```bash
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
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

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

```bash
# 1. Tools
command -v cosign >/dev/null || brew install cosign

# 2. Generate a keypair (interactive password prompt — can be empty for testing)
cosign generate-key-pair
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-public-key \
  --value "$(cat cosign.pub)" --type String --overwrite

# 3-6: same shape as cosign-kms, with --key cosign.key on `cosign sign`,
#      and integ test name integ.cosign-publickey.
```

`cosign.key` / `cosign.pub` are git-ignored. Do NOT commit them, and remove them in `cleanup-signature`.

## Mode: `signature-ecr-signing`

ECR Managed Signing auto-signs on push when a signing-configuration matches the repository. The integ uses `ECRDeployment` to copy a CDK asset into a signing-enabled repo so that the push triggers a signature.

**Regional gotcha**: `aws ecr put-signing-configuration` is not available in every region. If the API call returns `UnknownOperationException` or similar, abort and report the region — do not silently fall back.

**Permissions gotcha**: the caller needs `signer:*` including `signer:SignPayload`. Surface a friendly error if `put-signing-configuration` fails on `AccessDenied`.

```bash
# 1. Profile (reused with signature-notation)
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTestProfile \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Create a dedicated repo
REGION=$(aws configure get region)
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

# 5. Cleanup specific to this mode (always run, even on test failure)
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
# SSM params (cosign)
aws ssm delete-parameter --name /ecr-scan-verifier/cosign-kms-key-id 2>/dev/null || true
aws ssm delete-parameter --name /ecr-scan-verifier/cosign-public-key 2>/dev/null || true

# KMS: schedule deletion (minimum 7 days). Read the id from SSM if still present, else
# require the user to pass --kms-key-id <id> rather than guess.
# Only schedule deletion for keys this skill created — if uncertain, ASK first.

# Local cosign keypair
rm -f cosign.key cosign.pub
```

## Reporting

At the end of every run, print:

- Mode invoked + duration
- `ORIGINAL_STATE` and whether it was restored
- Test pass/fail counts (parse from `integ-runner` output)
- Any leftover side effects (e.g. `EcrScanVerifierTestProfile` left Active intentionally; signing-configuration disabled; `cosign.key` removed; etc.)

Never end with stale state silently. If a restore step was skipped or failed, say so explicitly.

## Important

- **Always operate on all three regions** (`us-east-1 us-east-2 us-west-2`) when toggling Inspector — partial toggles cause hard-to-debug test failures.
- **Poll, don't sleep** for state transitions — Inspector enable/disable propagation is variable (often >10 min for the scanning engine, even after `batch-get-account-status` reports the new state).
- **Never cancel `EcrScanVerifierTestProfile`** — cancellation is permanent and blocks future runs under the same name.
- **Never commit `cosign.key` / `cosign.pub`** — they're git-ignored, keep it that way.
- **Bootstrap repo uses immutable tags** — leftover Notation referrer tags from a failed `notation sign` MUST be deleted before retrying; do not work around with a fresh tag.
- When in doubt about which test to run, call `AskUserQuestion` rather than guess.
