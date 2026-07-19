#!/usr/bin/env bash
set -Eeuo pipefail

: "${QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS:?Set QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 to authorize live sandbox resources}"
[[ "$QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS" == "1" ]]
: "${QUANTUMFORGE_EXPECTED_ACCOUNT_ID:?Set the isolated AWS sandbox account ID}"

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
RUN_ID="${QUANTUMFORGE_RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
EVIDENCE_DIR="${1:-build/live-kms-evidence}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/tests/live/kms"
TMP_DIR="$(mktemp -d)"
TF_DATA_DIR="$TMP_DIR/tfdata"
STATE_PATH="$TMP_DIR/terraform.tfstate"
PLAN_PATH="$TMP_DIR/tfplan"
PRIVATE_DIR="$TMP_DIR/private"
OPENSSL_IMAGE="${OPENSSL_IMAGE:-alpine@sha256:9a341ff2287c54b86425cbee0141114d811ae69d88a36019087be6d896cef241}"
mkdir -p "$EVIDENCE_DIR" "$PRIVATE_DIR"

key_id=""
alias_name=""
destroy_succeeded=0

cleanup() {
  local rc="$?"
  set +e
  if [[ -d "$TF_DATA_DIR" ]]; then
    for _ in 1 2 3; do
      if TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" destroy -auto-approve -input=false \
        -var="aws_region=$AWS_REGION" -var="run_id=$RUN_ID" \
        > "$EVIDENCE_DIR/terraform-destroy.log" 2>&1; then
        destroy_succeeded=1
        break
      fi
      sleep 15
    done
  fi

  if [[ "$destroy_succeeded" -ne 1 && -n "$alias_name" ]]; then
    aws kms delete-alias --region "$AWS_REGION" --alias-name "$alias_name" >/dev/null 2>&1 || true
  fi
  if [[ "$destroy_succeeded" -ne 1 && -n "$key_id" ]]; then
    aws kms disable-key --region "$AWS_REGION" --key-id "$key_id" >/dev/null 2>&1 || true
    aws kms schedule-key-deletion --region "$AWS_REGION" --key-id "$key_id" --pending-window-in-days 7 >/dev/null 2>&1 || true
  fi

  if [[ -n "$key_id" ]]; then
    aws kms describe-key --region "$AWS_REGION" --key-id "$key_id" \
      --query 'KeyMetadata.{KeyId:KeyId,KeySpec:KeySpec,KeyUsage:KeyUsage,KeyState:KeyState,DeletionDate:DeletionDate}' \
      --output json > "$EVIDENCE_DIR/key-cleanup-status.json" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
  if [[ "$rc" -eq 0 && "$destroy_succeeded" -ne 1 ]]; then
    echo "Terraform cleanup did not complete" >&2
    exit 1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

actual_account_id="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$actual_account_id" != "$QUANTUMFORGE_EXPECTED_ACCOUNT_ID" ]]; then
  echo "Refusing live test in AWS account $actual_account_id; expected $QUANTUMFORGE_EXPECTED_ACCOUNT_ID" >&2
  exit 1
fi
export AWS_ACCOUNT_ID="$actual_account_id"

TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" init -input=false -lockfile=readonly \
  -backend-config="path=$STATE_PATH" > "$EVIDENCE_DIR/terraform-init.log"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" plan -input=false \
  -var="aws_region=$AWS_REGION" -var="run_id=$RUN_ID" \
  -out="$PLAN_PATH" > "$EVIDENCE_DIR/terraform-plan.log"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" show -json "$PLAN_PATH" \
  > "$EVIDENCE_DIR/plan.json"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" apply -auto-approve -input=false "$PLAN_PATH" \
  > "$EVIDENCE_DIR/terraform-apply.log"

key_id="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw key_id)"
alias_name="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw alias_name)"
key_arn="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw key_arn)"
key_spec="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw key_spec)"
[[ "$key_spec" == "ML_DSA_65" ]]

printf 'QuantumForge ML-DSA lifecycle test %s\n' "$RUN_ID" > "$PRIVATE_DIR/message.bin"
aws kms sign --region "$AWS_REGION" \
  --key-id "$key_id" \
  --message "fileb://$PRIVATE_DIR/message.bin" \
  --message-type RAW \
  --signing-algorithm ML_DSA_SHAKE_256 \
  --query Signature --output text \
  | base64 --decode > "$PRIVATE_DIR/signature.bin"

aws kms verify --region "$AWS_REGION" \
  --key-id "$key_id" \
  --message "fileb://$PRIVATE_DIR/message.bin" \
  --message-type RAW \
  --signature "fileb://$PRIVATE_DIR/signature.bin" \
  --signing-algorithm ML_DSA_SHAKE_256 \
  --query '{SignatureValid:SignatureValid,KeyId:KeyId,SigningAlgorithm:SigningAlgorithm}' \
  --output json > "$EVIDENCE_DIR/kms-verify.json"
jq -e '.SignatureValid == true and .SigningAlgorithm == "ML_DSA_SHAKE_256"' "$EVIDENCE_DIR/kms-verify.json" >/dev/null

aws kms get-public-key --region "$AWS_REGION" --key-id "$key_id" \
  --query PublicKey --output text | base64 --decode > "$PRIVATE_DIR/public-key.der"

docker run --rm \
  --volume "$PRIVATE_DIR:/work:ro" \
  "$OPENSSL_IMAGE" sh -ec '
    apk add --no-cache "openssl=3.5.7-r0" >/dev/null
    openssl version
    openssl pkey -pubin -inform DER -in /work/public-key.der -out /tmp/public-key.pem
    openssl pkeyutl -verify -pubin -inkey /tmp/public-key.pem \
      -in /work/message.bin -sigfile /work/signature.bin
  ' > "$EVIDENCE_DIR/openssl-verify.log" 2>&1
grep -q 'Signature Verified Successfully' "$EVIDENCE_DIR/openssl-verify.log"

jq -n \
  --arg status "assessment_complete" \
  --arg timestamp "$(date -u +%FT%TZ)" \
  --arg account_id "$actual_account_id" \
  --arg region "$AWS_REGION" \
  --arg key_arn "$key_arn" \
  --arg key_spec "$key_spec" \
  '{status:$status,timestamp:$timestamp,account_id:$account_id,region:$region,key_arn:$key_arn,key_spec:$key_spec,kms_verify:true,openssl_verify:true}' \
  > "$EVIDENCE_DIR/assessment-status.json"

echo "KMS ML-DSA lifecycle test passed; cleanup will schedule the key for deletion."
