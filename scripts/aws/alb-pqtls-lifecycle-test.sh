#!/usr/bin/env bash
set -Eeuo pipefail

: "${QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS:?Set QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 to authorize live sandbox resources}"
[[ "$QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS" == "1" ]]
: "${QUANTUMFORGE_EXPECTED_ACCOUNT_ID:?Set the isolated AWS sandbox account ID}"

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
RUN_ID="${QUANTUMFORGE_RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
EVIDENCE_DIR="${1:-build/live-alb-evidence}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/tests/live/alb-pqtls"
TMP_DIR="$(mktemp -d)"
TF_DATA_DIR="$TMP_DIR/tfdata"
STATE_PATH="$TMP_DIR/terraform.tfstate"
PLAN_PATH="$TMP_DIR/tfplan"
PRIVATE_DIR="$TMP_DIR/private"
OPENSSL_IMAGE="${OPENSSL_IMAGE:-alpine@sha256:9a341ff2287c54b86425cbee0141114d811ae69d88a36019087be6d896cef241}"
mkdir -p "$EVIDENCE_DIR" "$PRIVATE_DIR"

certificate_arn=""
load_balancer_arn=""
destroy_succeeded=0
certificate_deleted=0

cleanup() {
  local rc="$?"
  set +e
  if [[ -d "$TF_DATA_DIR" && -n "$certificate_arn" ]]; then
    for _ in 1 2 3; do
      if TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" destroy -auto-approve -input=false \
        -var="aws_region=$AWS_REGION" -var="run_id=$RUN_ID" -var="certificate_arn=$certificate_arn" \
        > "$EVIDENCE_DIR/terraform-destroy.log" 2>&1; then
        destroy_succeeded=1
        break
      fi
      sleep 20
    done
  fi
  if [[ -n "$certificate_arn" ]]; then
    for _ in 1 2 3; do
      if aws acm delete-certificate --region "$AWS_REGION" --certificate-arn "$certificate_arn" >/dev/null 2>&1; then
        certificate_deleted=1
        break
      fi
      sleep 10
    done
  fi

  jq -n \
    --arg timestamp "$(date -u +%FT%TZ)" \
    --argjson terraform_destroyed "$destroy_succeeded" \
    --argjson certificate_deleted "$certificate_deleted" \
    '{timestamp:$timestamp,terraform_destroyed:($terraform_destroyed == 1),certificate_deleted:($certificate_deleted == 1)}' \
    > "$EVIDENCE_DIR/cleanup-status.json"
  rm -rf "$TMP_DIR"
  if [[ "$rc" -eq 0 && ( "$destroy_succeeded" -ne 1 || "$certificate_deleted" -ne 1 ) ]]; then
    echo "ALB integration cleanup did not complete" >&2
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

docker run --rm --volume "$PRIVATE_DIR:/work" "$OPENSSL_IMAGE" sh -ec '
  apk add --no-cache "openssl=3.5.7-r0" >/dev/null
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=quantumforge.invalid" \
    -keyout /work/private-key.pem -out /work/certificate.pem
' > "$EVIDENCE_DIR/certificate-generation.log" 2>&1

certificate_arn="$(aws acm import-certificate --region "$AWS_REGION" \
  --certificate "fileb://$PRIVATE_DIR/certificate.pem" \
  --private-key "fileb://$PRIVATE_DIR/private-key.pem" \
  --tags Key=project,Value=quantumforge Key=environment,Value=integration-test Key=test-run,Value="$RUN_ID" \
  --query CertificateArn --output text)"

TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" init -input=false -lockfile=readonly \
  -backend-config="path=$STATE_PATH" > "$EVIDENCE_DIR/terraform-init.log"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" plan -input=false \
  -var="aws_region=$AWS_REGION" -var="run_id=$RUN_ID" -var="certificate_arn=$certificate_arn" \
  -out="$PLAN_PATH" > "$EVIDENCE_DIR/terraform-plan.log"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" show -json "$PLAN_PATH" \
  > "$EVIDENCE_DIR/plan.json"
TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" apply -auto-approve -input=false "$PLAN_PATH" \
  > "$EVIDENCE_DIR/terraform-apply.log"

load_balancer_arn="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw load_balancer_arn)"
dns_name="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw dns_name)"
ssl_policy="$(TF_DATA_DIR="$TF_DATA_DIR" terraform -chdir="$FIXTURE_DIR" output -raw ssl_policy)"
[[ "$ssl_policy" == "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09" ]]
aws elbv2 wait load-balancer-available --region "$AWS_REGION" --load-balancer-arns "$load_balancer_arn"

run_handshake() {
  local groups="$1"
  local output="$2"
  local expected_group="$3"
  for _ in $(seq 1 30); do
    if docker run --rm "$OPENSSL_IMAGE" sh -ec "
      apk add --no-cache 'openssl=3.5.7-r0' >/dev/null
      printf 'GET / HTTP/1.0\\r\\nHost: quantumforge.invalid\\r\\n\\r\\n' |
        openssl s_client -connect '$dns_name:443' -servername quantumforge.invalid \
          -tls1_3 -groups '$groups' -brief
    " > "$output" 2>&1; then
      if grep -Eq "(Negotiated TLS1.3 group:|Peer Temp Key:) $expected_group([, ]|$)" "$output"; then
        return 0
      fi
    fi
    sleep 10
  done
  cat "$output" >&2
  return 1
}

run_handshake "X25519MLKEM768" "$EVIDENCE_DIR/pq-handshake.log" "X25519MLKEM768"
run_handshake "X25519" "$EVIDENCE_DIR/classical-handshake.log" "X25519"

jq -n \
  --arg status "assessment_complete" \
  --arg timestamp "$(date -u +%FT%TZ)" \
  --arg account_id "$actual_account_id" \
  --arg region "$AWS_REGION" \
  --arg dns_name "$dns_name" \
  --arg ssl_policy "$ssl_policy" \
  '{status:$status,timestamp:$timestamp,account_id:$account_id,region:$region,dns_name:$dns_name,ssl_policy:$ssl_policy,pq_group:"X25519MLKEM768",classical_fallback_group:"X25519"}' \
  > "$EVIDENCE_DIR/assessment-status.json"

echo "ALB hybrid PQ-TLS and classical fallback handshakes passed; cleanup will now run."
