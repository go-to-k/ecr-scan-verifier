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
ASSET_HASH=$(cat cdk.out/NotationSignatureStack.assets.json | tr ',' '\n' | \
  grep '"imageTag"' | head -1 | cut -d'"' -f4)
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

#### Notation (ECR Managed Signing)

ECR's managed signing feature (`signing-configuration`) automatically signs images on push using AWS Signer. This test verifies that the construct can verify these automatically-signed images.

**Note:** This feature may not be available in all AWS regions yet. Check if your region supports `aws ecr put-signing-configuration` before proceeding.

**Prerequisites:**

- User must have `signer:*` permissions
- Same AWS Signer profile as above (`EcrScanVerifierTest`)

```bash
# 1. Create a signing profile (if not already created)
aws signer put-signing-profile \
  --profile-name EcrScanVerifierTest \
  --platform-id Notation-OCI-SHA384-ECDSA

# 2. Create ECR repository via CLI
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REPO_NAME="ecr-scan-verifier-integ-ecr-signing"
PROFILE_ARN=$(aws signer get-signing-profile \
  --profile-name EcrScanVerifierTest --query 'arn' --output text)

aws ecr create-repository --repository-name "${REPO_NAME}" || echo "Repository already exists"

# 3. Enable ECR managed signing (registry-level configuration)
# Create signing configuration JSON
cat > /tmp/signing-config.json <<EOF
{
  "rules": [
    {
      "signingProfileArn": "${PROFILE_ARN}",
      "repositoryFilters": [
        {
          "filter": "${REPO_NAME}",
          "filterType": "WILDCARD_MATCH"
        }
      ]
    }
  ]
}
EOF

aws ecr put-signing-configuration \
  --region "${REGION}" \
  --signing-configuration file:///tmp/signing-config.json

# Verify signing-configuration is enabled
aws ecr describe-signing-configuration --region "${REGION}"

# 4. Run the integ test
# This will:
#   - Build and push the Docker image to CDK bootstrap repository
#   - Deploy ECRDeployment which copies the image to signing-enabled repository
#     (ECR managed signing will automatically sign on push)
#   - Verify the signature using Notation
pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
SIGNING_PROFILE_ARN="${PROFILE_ARN}" REPO_NAME="${REPO_NAME}" \
  pnpm integ:signature:update --language javascript --test-regex "integ.ecr-signing.js$"

# 5. Cleanup - disable signing-configuration and delete repository
# Remove signing configuration (set to empty rules)
cat > /tmp/signing-config-empty.json <<EOF
{
  "rules": []
}
EOF

aws ecr put-signing-configuration \
  --region "${REGION}" \
  --signing-configuration file:///tmp/signing-config-empty.json

aws ecr delete-repository --repository-name "${REPO_NAME}" --force
```

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

# 2. Create a KMS key for signing and capture the key ID
KMS_KEY_ID=$(aws kms create-key \
  --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
  --query 'KeyMetadata.KeyId' --output text)
KMS_KEY_ARN=$(aws kms describe-key --key-id "${KMS_KEY_ID}" \
  --query 'KeyMetadata.Arn' --output text)

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
COSIGN_KMS_KEY_ID="${KMS_KEY_ID}" npx cdk synth --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
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

# 4. Sign the pushed image WITHOUT Rekor transparency log
# This matches the Lambda verification behavior (always skips Rekor)
# Create signing config without transparency log, then sign
curl -s https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
  jq 'del(.rekorTlogUrls)' > /tmp/signing-config.json

cosign sign --signing-config /tmp/signing-config.json --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
COSIGN_KMS_KEY_ID="${KMS_KEY_ID}" pnpm integ:signature:update --language javascript --test-regex "integ.cosign-kms.js$"
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

# 2. Generate a key pair
cosign generate-key-pair
# This creates cosign.key (private) and cosign.pub (public)
# Enter a password when prompted (can be empty for testing)

# 3. Build and synth to publish the Docker image asset only (no deploy)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"

pnpm tsc -p tsconfig.dev.json
cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
COSIGN_PUBLIC_KEY="$(cat cosign.pub)" npx cdk synth --app 'node test/integ/signature/integ.cosign-publickey.js' -o cdk.out
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

cosign sign --signing-config /tmp/signing-config.json --key cosign.key "${REGISTRY}/${REPO}@${DIGEST}"

# 5. Run the integ test
COSIGN_PUBLIC_KEY="$(cat cosign.pub)" pnpm integ:signature:update --language javascript --test-regex "integ.cosign-publickey.js$"
```

#### Cleanup

```bash
# Cancel the signing profile (cannot be deleted, but can be revoked)
aws signer cancel-signing-profile --profile-name EcrScanVerifierTest

# Schedule KMS key deletion (minimum 7-day waiting period)
KMS_KEY_ID=$(echo "${KMS_KEY_ARN}" | grep -o '[^/]*$')
aws kms schedule-key-deletion --key-id "${KMS_KEY_ID}" --pending-window-in-days 7

# Remove generated key pair
rm -f cosign.key cosign.pub
```
