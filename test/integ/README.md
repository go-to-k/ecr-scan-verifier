# Integration Tests

> **Shortcuts**:
>
> - For manual runs, source [`scripts/integ.sh`](../../scripts/integ.sh) once per shell. All the `for region in …` loops in this README collapse to helper calls (`inspector_status_all`, `inspector_enable_all` / `disable_all`, `wait_inspector_status_all`, `scan_on_push_set`, `wait_enhanced_engine_warmup`, `enhanced_run_with_retry`, `ecr_signing_setup` / `teardown`, `cleanup_signature_artifacts`).
> - In Claude Code, invoke the `/integ-test` skill (`.claude/skills/integ-test/`) to orchestrate the steps below — Inspector enable/disable + propagation waits, scan-on-push toggling, image signing, and cleanup. See [Using the `/integ-test` skill](#using-the-integ-test-skill) below.

Integration tests are split into three directories based on the required AWS account configuration.

- `basic/` — Basic ECR scanning
- `enhanced/` — Enhanced scanning (Amazon Inspector)
- `signature/` — Signature verification (Notation / Cosign)

Tests deploy stacks across multiple regions (`us-east-1`, `us-east-2`, `us-west-2`), so the scanning configuration must be changed in **all regions**.

## Bootstrap (run once per shell)

```bash
. scripts/integ.sh
```

This defines the helpers used throughout this document. The `REGIONS` array (`us-east-1 us-east-2 us-west-2`) is exported so commands like `inspector_*_all` and `scan_on_push_set` apply to all three at once.

## Important Note

Changing the ECR scanning configuration via `aws inspector2 enable/disable` may take a few minutes to propagate. After enabling or disabling Enhanced scanning, **verify the status has changed in all regions before running tests** (`wait_inspector_status_all` polls with a 5-minute cap).

Even after `batch-get-account-status` reports `ENABLED`, the Inspector scanning engine may need **additional time** — empirically **20–30 minutes** on a fresh enable — before newly pushed images are actually scanned and produce findings. The `wait_enhanced_engine_warmup` helper sleeps 20 min by default after a DISABLED→ENABLED transition, and `enhanced_run_with_retry` then retries the test up to 3 times with 10 min gaps. If `enhanced/` tests fail with empty or missing findings after that, the cause is not propagation lag — investigate.

## Check Current Environment

```bash
inspector_status_all
```

- All `ENABLED` → Run `enhanced/` tests as-is. Switch to DISABLED before running `basic/` tests.
- All `DISABLED` → Run `basic/` tests as-is. Switch to ENABLED before running `enhanced/` tests.
- Mixed → resolve the inconsistency before running anything.

## Running Tests

### Basic scanning (`basic/`)

Requires Enhanced scanning to be **DISABLED** in all regions.

#### Scan-on-push (`integ.scan-on-push`)

This test additionally requires scan-on-push to be enabled on the CDK bootstrap asset repository in all three regions. `pnpm integ:basic:update` runs **every** test under `basic/` including this one, so enable up front:

```bash
scan_on_push_set true
```

#### Running

```bash
# If currently ENABLED, disable first and wait for the flip
inspector_disable_all
wait_inspector_status_all DISABLED

# Verify (optional)
inspector_status_all

# Run tests
pnpm integ:basic
# or update snapshots
pnpm integ:basic:update

# Restore to ENABLED if it was originally enabled
inspector_enable_all
wait_inspector_status_all ENABLED
inspector_status_all

# Restore scan-on-push to default (if enabled above)
scan_on_push_set false
```

### Enhanced scanning (`enhanced/`)

Requires Enhanced scanning to be **ENABLED** in all regions.

```bash
# Capture pre-state — wait_enhanced_engine_warmup needs to know whether
# a real DISABLED -> ENABLED transition is happening (the engine only
# lags on fresh enable).
ORIGINAL_STATE_EAST1="$(inspector_status us-east-1)"

# If currently DISABLED, enable first and wait for the flip
inspector_enable_all
wait_inspector_status_all ENABLED
inspector_status_all

# Engine warmup (20 min by default, skipped if already ENABLED)
wait_enhanced_engine_warmup "$ORIGINAL_STATE_EAST1"

# Run with up to 3 attempts × 10 min gaps. This absorbs the warmup tail —
# NOT flaky tests. Stop manually if 3 attempts fail.
MAX_ATTEMPTS=3 RETRY_GAP_SECS=600 enhanced_run_with_retry pnpm integ:enhanced
# or update snapshots
MAX_ATTEMPTS=3 RETRY_GAP_SECS=600 enhanced_run_with_retry pnpm integ:enhanced:update

# Restore to DISABLED if it was originally disabled
inspector_disable_all
wait_inspector_status_all DISABLED
inspector_status_all
```

### Signature verification (`signature/`)

Requires additional setup for signing. Works with both Basic and Enhanced scanning (the tests themselves are state-agnostic w.r.t. Inspector).

> **Note on AWS Signer profiles:** Signer profiles cannot be deleted (only canceled), and a canceled profile cannot be reused for signing. We intentionally leave the `EcrScanVerifierTestProfile` profile Active across test runs so the same name is reusable (`put-signing-profile` is idempotent for Active profiles). If you already have a profile in `Canceled` state from a previous run, use a different `--profile-name` once (e.g. `EcrScanVerifierTestProfile2`) and update subsequent commands accordingly.

The signature flows below are mostly per-mode and don't share enough structure for helpers — they remain raw commands. Use `cleanup_signature_artifacts` once at the end of the day to tear down SSM/KMS state.

#### Notation (AWS Signer)

```bash
# 1. Create a signing profile
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTestProfile \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Install notation CLI + AWS Signer plugin
#    https://docs.aws.amazon.com/signer/latest/developerguide/image-signing-prerequisites.html

# Download and install AWS Signer installer (includes notation + plugin + trust store)
# For Apple Silicon (arm64) - default for modern Macs:
curl -o aws-signer-notation-cli.pkg https://d2hvyiie56hcat.cloudfront.net/darwin/arm64/installer/latest/aws-signer-notation-cli_arm64.pkg
sudo installer -pkg aws-signer-notation-cli.pkg -target /

# For Intel Macs (amd64):
# curl -o aws-signer-notation-cli.pkg https://d2hvyiie56hcat.cloudfront.net/darwin/amd64/installer/latest/aws-signer-notation-cli_amd64.pkg
# sudo installer -pkg aws-signer-notation-cli.pkg -target /

# Verify installation
notation version
notation plugin ls

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT="$(account_id)"
REGION="$(default_region)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTestProfile --query 'arn' --output text)

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
npx cdk synth --app 'node test/integ/signature/integ.notation.js' -o cdk.out
npx cdk-assets -p cdk.out/NotationSignatureStack.assets.json publish

# 4. Sign the pushed image with notation
# Get the digest of the test fixture image (not the Lambda function image)
# The asset hash is the imageTag used in the test
ASSET_HASH=$(cat cdk.out/NotationSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password | notation login --username AWS --password-stdin "${REGISTRY}"

# If a previous `notation sign` attempt partially succeeded (e.g. failed at the
# signing step but already pushed the referrers index tag), the next run will
# fail with `tag invalid: ... already exists ... cannot be overwritten because
# the tag is immutable` because the CDK bootstrap ECR repository uses immutable
# tags. Delete the leftover referrer tag and retry:
#   REFERRER_TAG="sha256-${DIGEST#sha256:}"
#   aws ecr batch-delete-image --repository-name "${REPO}" \
#     --image-ids imageTag="${REFERRER_TAG}"
notation sign \
  --plugin com.amazonaws.signer.notation.plugin \
  --id "${PROFILE_ARN}" \
  "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the Notation integ test
pnpm integ:signature:update --language javascript --test-regex "integ.notation.js$"
```

#### Notation (ECR Managed Signing)

ECR's managed signing feature (`signing-configuration`) automatically signs images on push using AWS Signer. This test verifies that the construct can verify these automatically-signed images.

**Implementation:** This test uses `ECRDeployment` to copy a CDK Docker image asset from the bootstrap repository to the signing-enabled repository. The ECRDeployment Lambda role is granted `signer:SignPayload` permission, allowing ECR managed signing to work automatically during the image push.

**Note:** This feature may not be available in all AWS regions yet. Check if your region supports `aws ecr put-signing-configuration` before proceeding.

**Prerequisites:**

- User must have `signer:*` permissions (including `signer:SignPayload`)
- Same AWS Signer profile as above (`EcrScanVerifierTestProfile`)

```bash
# 1. Create signing profile, dedicated repo, and signing-configuration in one go.
#    Uses ECR_SIGNING_REPO_NAME (default: ecr-scan-verifier-integ-ecr-signing).
ecr_signing_setup

# 2. Run the integ test (uses ECRDeployment with signer:SignPayload permission)
pnpm integ:signature:update --language javascript --test-regex "integ.ecr-signing.js$"

# 3. Always tear down — even if the test failed — to leave the registry clean.
ecr_signing_teardown
```

The teardown disables the signing-configuration and deletes the dedicated repo. The AWS Signer profile is left Active intentionally (see profile-reuse note above).

#### Cosign (KMS)

**Note on Rekor Transparency Log:**
This implementation always skips Rekor transparency log verification for reliability in AWS Lambda
environments. The cryptographic signature is still verified using the KMS key.

- Sign with: `cosign sign --tlog-upload=false --key "awskms:///${KMS_KEY_ARN}" IMAGE`
- Verification works offline and in VPC environments without internet access
- Faster verification without network calls to Rekor service
- If you require Rekor transparency log verification for compliance, consider using Notation with AWS Signer instead

**Setup:**

```bash
# 1. Install cosign
brew install cosign  # macOS

# 2. Create a KMS key for signing and store key ID in SSM Parameter Store
KMS_KEY_ID=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --query 'KeyMetadata.KeyId' --output text)
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-kms-key-id \
  --value "${KMS_KEY_ID}" --type String --overwrite
KMS_KEY_ARN=$(aws kms describe-key --key-id "${KMS_KEY_ID}" \
  --query 'KeyMetadata.Arn' --output text)

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT="$(account_id)"
REGION="$(default_region)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
npx cdk synth --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish

# 4. Sign the pushed image with cosign
# Get the digest of the test fixture image (not the Lambda function image)
# The asset hash is the imageTag used in the test
ASSET_HASH=$(cat cdk.out/CosignKmsSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password --region ${REGION} | cosign login --username AWS --password-stdin "${REGISTRY}"

# Sign the pushed image WITHOUT Rekor transparency log
# This matches the Lambda verification behavior (always skips Rekor)
# Create signing config without transparency log, then sign
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json

cosign sign --signing-config /tmp/signing-config.json --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
pnpm integ:signature:update --language javascript --test-regex "integ.cosign-kms.js$"
```

#### Cosign (Public Key)

**Note on Rekor Transparency Log:**
This implementation always skips Rekor transparency log verification for reliability in AWS Lambda
environments. The cryptographic signature is still verified using the public key.

- Sign with: `cosign sign --tlog-upload=false --key cosign.key IMAGE`
- Verification works offline and in VPC environments without internet access
- Faster verification without network calls to Rekor service
- If you require Rekor transparency log verification for compliance, consider using Notation with AWS Signer instead

**Setup:**

```bash
# 1. Install cosign
brew install cosign  # macOS

# 2. Generate a key pair and store the public key in SSM Parameter Store.
#    COSIGN_PASSWORD="" skips the interactive password prompt — required
#    for unattended runs.
COSIGN_PASSWORD="" cosign generate-key-pair
# This creates cosign.key (private) and cosign.pub (public)
aws ssm put-parameter \
  --name /ecr-scan-verifier/cosign-public-key \
  --value "$(cat cosign.pub)" --type String --overwrite

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT="$(account_id)"
REGION="$(default_region)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
npx cdk synth --app 'node test/integ/signature/integ.cosign-publickey.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignPublicKeySignatureStack.assets.json publish

# 4. Sign the pushed image with cosign
# Get the digest of the test fixture image (not the Lambda function image)
# The asset hash is the imageTag used in the test
ASSET_HASH=$(cat cdk.out/CosignPublicKeySignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password --region ${REGION} | cosign login --username AWS --password-stdin "${REGISTRY}"

# Sign the pushed image WITHOUT Rekor transparency log
# This matches the Lambda verification behavior (always skips Rekor)
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json

COSIGN_PASSWORD="" cosign sign --signing-config /tmp/signing-config.json --key cosign.key "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
pnpm integ:signature:update --language javascript --test-regex "integ.cosign-publickey.js$"
```

#### Cleanup

```bash
# AWS Signer profiles cannot be deleted. We leave the profile Active so it can be
# reused on the next test run; cancel manually only if you no longer need it.
# (Once canceled, the profile name is permanently unusable for signing.)

# Deletes SSM params, schedules KMS key deletion (7-day pending window),
# and removes the local cosign keypair. The function resolves the KMS key id
# from SSM before deleting the param, and skips KMS deletion with a WARN if
# the id can't be recovered.
cleanup_signature_artifacts
```

## Using the `/integ-test` skill

In Claude Code, the [`/integ-test` skill](../../.claude/skills/integ-test/SKILL.md) wraps every workflow in this README.

### Syntax

```text
/integ-test <mode> [--snapshot-only] [--no-restore]
```

If invoked without arguments, the skill asks (1) which mode and (2) whether to run snapshot-only via `AskUserQuestion`.

### Defaults

- **Deploy is the default.** Each mode does its full AWS orchestration (Inspector toggle, signing setup, etc.) and ends with restore + reporting.
- `--snapshot-only` collapses any mode to a single `pnpm integ:<mode>` call (template comparison only, no AWS calls, no state changes).

### Modes

| Mode | What it does (deploy) |
| --- | --- |
| `status` | Print per-region Inspector state and recommend which directory is ready. No state changes. |
| `basic` | Disable Inspector, enable scan-on-push, run `pnpm integ:basic:update`, restore scan-on-push, restore Inspector. |
| `enhanced` | Enable Inspector, wait 20 min for engine warmup on fresh enable, run with up to 3 attempts × 10 min gaps, restore. |
| `signature` | Run all four signature sub-modes back-to-back. Per-mode pass/fail collected without short-circuiting. |
| `signature-notation` | Sign with Notation (AWS Signer) and run `integ.notation`. |
| `signature-cosign-kms` | Sign with Cosign + KMS and run `integ.cosign-kms`. |
| `signature-cosign-publickey` | Sign with Cosign + local keypair and run `integ.cosign-publickey`. |
| `signature-ecr-signing` | Set up ECR Managed Signing, run `integ.ecr-signing`, tear down (even on failure). |
| `all` | Run everything end-to-end (`enhanced` → all signatures → `basic`), always restore, auto-cleanup. |
| `cleanup-signature` | Run `cleanup_signature_artifacts` (delete SSM params, schedule KMS deletion, remove local cosign keys). |

### Flags

| Flag | Effect |
| --- | --- |
| `--snapshot-only` | Skip all AWS orchestration; just run `pnpm integ:<mode>` (template comparison). |
| `--no-restore` | Skip Inspector state restoration at the end. Useful when chaining modes. **Ignored by `all`**, which always restores. |

### Examples

```text
/integ-test status                       # triage only
/integ-test basic --snapshot-only        # template compare only
/integ-test basic                        # full deploy: flip Inspector, scan-on-push, restore
/integ-test enhanced                     # deploy with warmup + retries
/integ-test signature                    # deploy all four signature modes
/integ-test all                          # everything end-to-end (~45-80 min)
/integ-test cleanup-signature            # tear down SSM/KMS at end of day
```

### Time budget (deploy mode)

| Mode | Approx wall-clock |
| --- | --- |
| `basic` | ~5–10 min |
| `enhanced` | ~20–40 min on fresh enable; ~5–10 min otherwise |
| Each `signature-*` | ~3–5 min |
| `all` | ~45–80 min depending on warmup and retries |

`--snapshot-only` is always under a minute per mode.
