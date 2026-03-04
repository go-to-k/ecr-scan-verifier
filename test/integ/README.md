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

Requires additional setup for signing. Works with both Basic and Enhanced scanning.

#### Notation (AWS Signer)

```bash
# 1. Create a signing profile
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTest \
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
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTest --query 'arn' --output text)

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
npx cdk synth --app 'node test/integ/signature/integ.notation.js' -o cdk.out
npx cdk-assets -p cdk.out/NotationSignatureStack.assets.json publish

# 4. Sign the pushed image with notation
# Get the digest of the test fixture image (not the Lambda function image)
# The asset hash is the imageTag used in the test
ASSET_HASH=$(grep -A 10 '"id":.*"DockerImage"' cdk.out/NotationSignatureStack.assets.json | \
  grep '"imageTag"' | cut -d'"' -f4)
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --image-ids imageTag="${ASSET_HASH}" \
  --query 'imageDetails[0].imageDigest' --output text)

aws ecr get-login-password | notation login --username AWS --password-stdin "${REGISTRY}"
notation sign \
  --plugin com.amazonaws.signer.notation.plugin \
  --id "${PROFILE_ARN}" \
  "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the Notation integ test
pnpm integ:signature:update --language javascript --test-regex "integ.notation.js$"
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

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
npx cdk synth --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish

# 4. Sign the pushed image with cosign
DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
  --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageDigest' --output text)
aws ecr get-login-password | cosign login --username AWS --password-stdin "${REGISTRY}"
cosign sign --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" pnpm integ:signature:update --language javascript --test-regex "integ.cosign-kms.js$"
```

#### Cleanup

```bash
# Cancel the signing profile (cannot be deleted, but can be revoked)
aws signer cancel-signing-profile --profile-name EcrScanVerifierTest

# Schedule KMS key deletion (minimum 7-day waiting period)
KMS_KEY_ID=$(echo "${KMS_KEY_ARN}" | grep -o '[^/]*$')
aws kms schedule-key-deletion --key-id "${KMS_KEY_ID}" --pending-window-in-days 7
```
