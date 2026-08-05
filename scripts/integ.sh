#!/usr/bin/env bash
# Shared helpers for ecr-scan-verifier integ test orchestration.
#
# Source this from a shell or from the /integ-test skill:
#   . scripts/integ.sh
#
# Functions are intentionally small and idempotent so the skill can chain
# them without re-deriving region lists, account ids, or polling loops.

set -u

REGIONS=(us-east-1 us-east-2 us-west-2)

# Resolves the caller account id, retrying transient STS failures. A raw
# `get-caller-identity` returns an empty string on network flakiness, which
# silently corrupts every repository name derived from it — so validate the
# value and fail loudly (non-zero) instead of echoing garbage.
account_id() {
  local id attempt
  for attempt in 1 2 3; do
    id="$(aws sts get-caller-identity --query Account --output text)" || id=""
    if [ -n "$id" ] && [ "$id" != "None" ]; then
      echo "$id"
      return 0
    fi
    [ "$attempt" -lt 3 ] && sleep 5
  done
  echo "ERROR: account_id: could not resolve account id after 3 attempts" >&2
  return 1
}

default_region() {
  aws configure get region
}

# --- Inspector (Enhanced scanning) ------------------------------------------

inspector_status() {
  local region="$1"
  aws inspector2 batch-get-account-status \
    --region "$region" \
    --query 'accounts[0].resourceState.ecr.status' \
    --output text
}

inspector_status_all() {
  for region in "${REGIONS[@]}"; do
    echo "$region: $(inspector_status "$region")"
  done
}

inspector_enable_all() {
  for region in "${REGIONS[@]}"; do
    aws inspector2 enable --resource-types ECR --region "$region"
  done
}

inspector_disable_all() {
  for region in "${REGIONS[@]}"; do
    aws inspector2 disable --resource-types ECR --region "$region"
  done
}

# Poll one region until inspector status equals $target. Cap at 5 min so we
# fail loudly on stuck transitions instead of hanging.
wait_inspector_status() {
  local region="$1" target="$2" i=0
  while [ "$(inspector_status "$region")" != "$target" ]; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
      echo "ERROR: $region did not reach $target after 5 min" >&2
      return 1
    fi
    sleep 15
  done
}

wait_inspector_status_all() {
  local target="$1"
  for region in "${REGIONS[@]}"; do
    wait_inspector_status "$region" "$target" || return 1
  done
}

# --- scan-on-push on the CDK bootstrap asset repo ---------------------------

# Usage: scan_on_push_set true|false
# Returns non-zero if the account id cannot be resolved or if the call fails
# in any region, so callers can surface a half-applied toggle instead of
# assuming it succeeded.
scan_on_push_set() {
  local enabled="$1"
  local account rc=0
  account="$(account_id)" || {
    echo "ERROR: scan_on_push_set ${enabled}: aborting, account id unresolved" >&2
    return 1
  }
  for region in "${REGIONS[@]}"; do
    aws ecr put-image-scanning-configuration \
      --repository-name "cdk-hnb659fds-container-assets-${account}-${region}" \
      --image-scanning-configuration "scanOnPush=${enabled}" \
      --region "$region" || rc=1
  done
  if [ "$rc" -ne 0 ]; then
    echo "ERROR: scan_on_push_set ${enabled}: failed in at least one region" >&2
  fi
  return "$rc"
}

# Ensure old fixture images stay scannable: Inspector only scans images
# within the ECR re-scan duration (a fresh `inspector2 enable` can reset it
# to DAYS_14). Fixture images older than that window are then NEVER scanned
# and enhanced tests time out deterministically. Call this AFTER
# inspector_enable_all. Usage: inspector_rescan_set [LIFETIME]
inspector_rescan_set() {
  local duration="${1:-LIFETIME}"
  for region in "${REGIONS[@]}"; do
    aws inspector2 update-configuration --region "$region" \
      --ecr-configuration "{\"rescanDuration\":\"${duration}\",\"pullDateRescanDuration\":\"DAYS_180\"}"
  done
  for region in "${REGIONS[@]}"; do
    echo "$region: $(aws inspector2 get-configuration --region "$region" \
      --query 'ecrConfiguration.rescanDurationState.rescanDuration' --output text)"
  done
}

# --- Enhanced engine warmup (DISABLED -> ENABLED) ---------------------------
#
# `batch-get-account-status` flipping to ENABLED is not the same as the
# scanning engine being ready — empirically the lag is often 20-30 min on
# a fresh enable. wait_enhanced_engine_warmup absorbs that with a long
# initial sleep; enhanced_run_with_retry then retries the test up to N
# more times with a fixed gap between attempts.

# Initial wait after a DISABLED -> ENABLED transition. Skip if already
# enabled (no transition happened).
# Args: $1 = ORIGINAL_STATE (ENABLED|DISABLED), $2 = seconds (default 1200)
wait_enhanced_engine_warmup() {
  local original_state="$1" secs="${2:-1200}"
  if [ "$original_state" = "DISABLED" ]; then
    echo "Inspector engine warmup: sleeping ${secs}s after fresh enable..."
    sleep "$secs"
  fi
}

# Run `$@` (the test command). On failure, sleep $RETRY_GAP_SECS and retry,
# up to $MAX_ATTEMPTS total attempts. Defaults: 3 attempts, 600s gap.
# Tuned for "Inspector engine still warming up" — NOT for catching flaky
# tests. If real findings change, surface them; don't burn time retrying.
enhanced_run_with_retry() {
  local max="${MAX_ATTEMPTS:-3}" gap="${RETRY_GAP_SECS:-600}" attempt=1
  while true; do
    echo "Attempt ${attempt}/${max}: $*"
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$max" ]; then
      echo "ERROR: failed after ${max} attempts across ~$((max * gap / 60)) min of waits." >&2
      echo "       Stop waiting — the cause is not propagation lag." >&2
      return 1
    fi
    echo "Attempt ${attempt} failed. Sleeping ${gap}s before retry..."
    sleep "$gap"
    attempt=$((attempt + 1))
  done
}

# --- Signature test cleanup -------------------------------------------------
#
# Cleans up shared signature-test artifacts. AWS Signer profile is left
# Active on purpose (cancellation is permanent and would block future runs).

cleanup_signature_artifacts() {
  local key_id
  key_id="$(aws ssm get-parameter --name /ecr-scan-verifier/cosign-kms-key-id \
    --query 'Parameter.Value' --output text 2>/dev/null || true)"

  aws ssm delete-parameter --name /ecr-scan-verifier/cosign-kms-key-id 2>/dev/null || true
  aws ssm delete-parameter --name /ecr-scan-verifier/cosign-public-key 2>/dev/null || true

  if [ -n "$key_id" ]; then
    aws kms schedule-key-deletion --key-id "$key_id" --pending-window-in-days 7
  else
    echo "WARN: KMS key id not in SSM. Ask the user before scheduling deletion." >&2
  fi

  rm -f cosign.key cosign.pub
}

# --- signature-ecr-signing repo setup / teardown ----------------------------

ECR_SIGNING_REPO_NAME="${ECR_SIGNING_REPO_NAME:-ecr-scan-verifier-integ-ecr-signing}"
SIGNER_PROFILE_NAME="${SIGNER_PROFILE_NAME:-EcrScanVerifierTestProfile}"

# Idempotent-ish wrapper. `put-signing-profile` is NOT actually idempotent
# (returns ProfileAlreadyExists for an existing Active profile), so check
# first and only create if missing. Echoes the ARN on stdout.
# Returns non-zero if the profile cannot be ensured — callers using
# `var=$(signer_profile_ensure)` should also check `[ -n "$var" ]` since
# command substitution swallows the inner exit code by default.
signer_profile_ensure() {
  local arn
  arn="$(aws signer get-signing-profile --profile-name "$SIGNER_PROFILE_NAME" \
    --query 'arn' --output text 2>/dev/null || true)"
  if [ -z "$arn" ] || [ "$arn" = "None" ]; then
    aws signer put-signing-profile \
      --profile-name "$SIGNER_PROFILE_NAME" \
      --platform-id Notation-OCI-SHA384-ECDSA >&2 || return 1
    arn="$(aws signer get-signing-profile --profile-name "$SIGNER_PROFILE_NAME" \
      --query 'arn' --output text 2>/dev/null || true)"
  fi
  if [ -z "$arn" ] || [ "$arn" = "None" ]; then
    echo "ERROR: signer_profile_ensure: could not resolve ARN for $SIGNER_PROFILE_NAME" >&2
    return 1
  fi
  echo "$arn"
}

# Build the cosign signing-config the Lambda verifier expects: no rekor
# (transparency log), no fulcio CA, no OIDC, no TSA. cosign 3.x will try
# keyless flows even with --key if these fields are present, which manifests
# as a hung "Signing artifact..." with no further output. Stripping them
# lets a `--key`-based sign complete.
cosign_minimal_signing_config() {
  local out="${1:-/tmp/signing-config.json}"
  curl -fsSL https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/signing_config.v0.2.json | \
    jq 'del(.rekorTlogUrls, .oidcUrls, .caUrls, .tsaUrls)' > "$out"
  echo "$out"
}

ecr_signing_setup() {
  local region profile_arn
  region="$(default_region)"
  profile_arn="$(signer_profile_ensure)"
  aws ecr create-repository --repository-name "$ECR_SIGNING_REPO_NAME" 2>/dev/null || true

  local cfg=/tmp/ecr-scan-verifier-signing-config.json
  cat > "$cfg" <<EOF
{
  "rules": [
    {
      "signingProfileArn": "${profile_arn}",
      "repositoryFilters": [
        { "filter": "${ECR_SIGNING_REPO_NAME}", "filterType": "WILDCARD_MATCH" }
      ]
    }
  ]
}
EOF
  aws ecr put-signing-configuration --region "$region" \
    --signing-configuration "file://${cfg}"
  aws ecr get-signing-configuration --region "$region"
}

ecr_signing_teardown() {
  local region cfg=/tmp/ecr-scan-verifier-signing-config-empty.json
  region="$(default_region)"
  printf '{ "rules": [] }\n' > "$cfg"
  aws ecr put-signing-configuration --region "$region" \
    --signing-configuration "file://${cfg}" || true
  aws ecr delete-repository --repository-name "$ECR_SIGNING_REPO_NAME" --force || true
}
