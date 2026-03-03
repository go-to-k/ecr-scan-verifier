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
aws ecr put-account-setting --name CONTAINER_REGISTRAR_SIGNING --value ENABLED
aws ecr put-registry-signing-configuration \
  --signing-profiles '[{"signingProfileName": "EcrScanVerifierTest", "signingProfileVersionArn": "<version-arn>"}]'

# 3. Run the Notation integ test
pnpm integ:signature:update -- \
  --test integ.notation \
  -c signerProfileArn=arn:aws:signer:<region>:<account>:/signing-profiles/EcrScanVerifierTest
```

#### Cosign (KMS)

```bash
# 1. Install cosign
brew install cosign  # macOS

# 2. Create a KMS key for signing
aws kms create-key --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256
# Note the Arn from the output

# 3. Push the image first (cdk deploy creates the ECR repo and pushes the image)
#    Then sign the image with cosign:
aws ecr get-login-password | cosign login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
cosign sign --key awskms:///<kms-key-arn> <account>.dkr.ecr.<region>.amazonaws.com/<repo>@<digest>

# 4. Run the Cosign KMS integ test
pnpm integ:signature:update -- \
  --test integ.cosign-kms \
  -c cosignKmsKeyArn=arn:aws:kms:<region>:<account>:key/<key-id>
```
