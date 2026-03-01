# Integration Tests

Integration tests are split into two directories based on the required AWS account scanning configuration.

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
