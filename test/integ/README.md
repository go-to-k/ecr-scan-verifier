# Integration Tests

Integration tests are split into three directories based on the required AWS account configuration.

- `basic/` — Basic ECR scanning
- `enhanced/` — Enhanced scanning (Amazon Inspector)
- `signature/` — Signature verification (Notation / Cosign)

Tests deploy stacks across multiple regions (e.g. `us-east-1`, `us-east-2`, `us-west-2`), so the scanning configuration must be changed in **all regions**.

## Important Note

Changing the ECR scanning configuration via `aws inspector2 enable/disable` may take a few minutes to propagate. After enabling or disabling Enhanced scanning, **verify the status has changed in all regions before running tests**.

## Check Current Environment

Before running tests, check whether Enhanced scanning (Amazon Inspector) is currently enabled or disabled in all regions:

```bash
for region in us-east-1 us-east-2 us-west-2; do
  echo "$region: $(aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text)"
done
```

- `ENABLED` → Run `enhanced/` tests as-is. Switch to DISABLED before running `basic/` tests.
- `DISABLED` → Run `basic/` tests as-is. Switch to ENABLED before running `enhanced/` tests.

## Running Tests

### Basic scanning (`basic/`)

Requires Enhanced scanning to be **DISABLED** in all regions.

```bash
# If currently ENABLED, disable first
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 disable --resource-types ECR --region "$region"
done

# Wait until status becomes DISABLED in all regions
for region in us-east-1 us-east-2 us-west-2; do
  echo "$region: $(aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text)"
done

# Run tests
pnpm integ:basic
# or update snapshots
pnpm integ:basic:update

# Restore to ENABLED if it was originally enabled
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 enable --resource-types ECR --region "$region"
done

for region in us-east-1 us-east-2 us-west-2; do
  echo "$region: $(aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text)"
done
```

### Enhanced scanning (`enhanced/`)

Requires Enhanced scanning to be **ENABLED** in all regions.

```bash
# If currently DISABLED, enable first
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 enable --resource-types ECR --region "$region"
done

# Wait until status becomes ENABLED in all regions
for region in us-east-1 us-east-2 us-west-2; do
  echo "$region: $(aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text)"
done

# Run tests
pnpm integ:enhanced
# or update snapshots
pnpm integ:enhanced:update

# Restore to DISABLED if it was originally disabled
for region in us-east-1 us-east-2 us-west-2; do
  aws inspector2 disable --resource-types ECR --region "$region"
done

for region in us-east-1 us-east-2 us-west-2; do
  echo "$region: $(aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text)"
done
```

### Signature verification (`signature/`)

Requires Enhanced scanning to be **DISABLED** and additional setup for signing.

#### Notation (AWS Signer)

```bash
# 1. Create a signing profile
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTest \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Enable ECR Managed Signing (auto-signs images on push)
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTest \
  --query 'arn' --output text)
aws ecr put-signing-configuration \
  --signing-configuration "{\"rules\":[{\"signingProfileArn\":\"${PROFILE_ARN}\"}]}"

# 3. Run the Notation integ test
SIGNER_PROFILE_ARN="${PROFILE_ARN}" pnpm integ:signature:update \
  --language javascript --test-regex integ.notation.js
```

#### Cosign (KMS)

```bash
# 1. Install cosign
brew install cosign  # macOS

# 2. Create a KMS key for signing and capture the ARN
KMS_KEY_ARN=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --query 'KeyMetadata.Arn' --output text)

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" npx cdk synth \
  --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish

# 4. Sign the pushed image with cosign
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageDigest' --output text)
aws ecr get-login-password | cosign login --username AWS --password-stdin "${REGISTRY}"
cosign sign --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" pnpm integ:signature:update \
  --language javascript --test-regex integ.cosign-kms.js
```

#### Cleanup

```bash
# Remove ECR Managed Signing configuration
aws ecr delete-signing-configuration

# Cancel the signing profile (cannot be deleted, but can be revoked)
aws signer cancel-signing-profile --profile-name EcrScanVerifierTest

# Schedule KMS key deletion (minimum 7-day waiting period)
KMS_KEY_ID=$(echo "${KMS_KEY_ARN}" | grep -o '[^/]*$')
aws kms schedule-key-deletion --key-id "${KMS_KEY_ID}" --pending-window-in-days 7
```
