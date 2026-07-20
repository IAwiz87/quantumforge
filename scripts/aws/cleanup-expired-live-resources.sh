#!/usr/bin/env bash
# shellcheck disable=SC2016 # JMESPath boolean literals intentionally use backticks.
set -Eeuo pipefail

: "${QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS:?Set QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 to authorize sandbox cleanup}"
[[ "$QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS" == "1" ]]
: "${QUANTUMFORGE_EXPECTED_ACCOUNT_ID:?Set the isolated AWS sandbox account ID}"

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
RUN_ID_FILTER=""
if [[ "${1:-}" == "--run-id" ]]; then
  RUN_ID_FILTER="${2:?usage: cleanup-expired-live-resources.sh [--run-id RUN_ID]}"
elif [[ -n "${1:-}" ]]; then
  echo "usage: cleanup-expired-live-resources.sh [--run-id RUN_ID]" >&2
  exit 2
fi

actual_account_id="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$actual_account_id" != "$QUANTUMFORGE_EXPECTED_ACCOUNT_ID" ]]; then
  echo "Refusing cleanup: caller is not the expected isolated sandbox account" >&2
  exit 1
fi

now="$(date -u +%FT%TZ)"
list_candidates() {
  aws resourcegroupstaggingapi get-resources \
    --region "$AWS_REGION" \
    --tag-filters \
      Key=project,Values=quantumforge \
      Key=environment,Values=integration-test \
    --output json |
    jq -r --arg run_id "$RUN_ID_FILTER" --arg now "$now" '
      .ResourceTagMappingList[] |
      . as $resource |
      (reduce .Tags[] as $tag ({}; .[$tag.Key] = $tag.Value)) as $tags |
      select(
        if $run_id != "" then
          $tags["test-run"] == $run_id
        else
          ($tags["expires-at"] // "") != "" and $tags["expires-at"] <= $now
        end
      ) |
      $resource.ResourceARN
    '
}

try_delete() {
  "$@" >/dev/null 2>&1 || return 0
}

cleanup_arn() {
  local arn="$1"
  local resource_id
  local state
  local alias_name
  local vpc_id
  local association_id

  case "$arn" in
    *:elasticloadbalancing:*:listener/*)
      try_delete aws elbv2 delete-listener --region "$AWS_REGION" --listener-arn "$arn"
      ;;
    *:elasticloadbalancing:*:loadbalancer/*)
      try_delete aws elbv2 delete-load-balancer --region "$AWS_REGION" --load-balancer-arn "$arn"
      ;;
    *:elasticloadbalancing:*:targetgroup/*)
      try_delete aws elbv2 delete-target-group --region "$AWS_REGION" --target-group-arn "$arn"
      ;;
    *:acm:*:certificate/*)
      try_delete aws acm delete-certificate --region "$AWS_REGION" --certificate-arn "$arn"
      ;;
    *:ec2:*:route-table/*)
      resource_id="${arn##*/}"
      while read -r association_id; do
        [[ -n "$association_id" && "$association_id" != "None" ]] || continue
        try_delete aws ec2 disassociate-route-table --region "$AWS_REGION" \
          --association-id "$association_id"
      done < <(aws ec2 describe-route-tables --region "$AWS_REGION" \
        --route-table-ids "$resource_id" \
        --query 'RouteTables[0].Associations[?Main!=`true`].RouteTableAssociationId' \
        --output text 2>/dev/null | tr '\t' '\n')
      try_delete aws ec2 delete-route-table --region "$AWS_REGION" --route-table-id "$resource_id"
      ;;
    *:ec2:*:internet-gateway/*)
      resource_id="${arn##*/}"
      while read -r vpc_id; do
        [[ -n "$vpc_id" && "$vpc_id" != "None" ]] || continue
        try_delete aws ec2 detach-internet-gateway --region "$AWS_REGION" \
          --internet-gateway-id "$resource_id" --vpc-id "$vpc_id"
      done < <(aws ec2 describe-internet-gateways --region "$AWS_REGION" \
        --internet-gateway-ids "$resource_id" \
        --query 'InternetGateways[0].Attachments[].VpcId' \
        --output text 2>/dev/null | tr '\t' '\n')
      try_delete aws ec2 delete-internet-gateway --region "$AWS_REGION" \
        --internet-gateway-id "$resource_id"
      ;;
    *:ec2:*:subnet/*)
      try_delete aws ec2 delete-subnet --region "$AWS_REGION" --subnet-id "${arn##*/}"
      ;;
    *:ec2:*:security-group/*)
      try_delete aws ec2 delete-security-group --region "$AWS_REGION" --group-id "${arn##*/}"
      ;;
    *:ec2:*:vpc/*)
      try_delete aws ec2 delete-vpc --region "$AWS_REGION" --vpc-id "${arn##*/}"
      ;;
    *:kms:*:key/*)
      resource_id="${arn##*/}"
      while read -r alias_name; do
        [[ -n "$alias_name" && "$alias_name" != "None" ]] || continue
        if [[ "$alias_name" == alias/quantumforge-live-* ]]; then
          try_delete aws kms delete-alias --region "$AWS_REGION" --alias-name "$alias_name"
        fi
      done < <(aws kms list-aliases --region "$AWS_REGION" --key-id "$resource_id" \
        --query 'Aliases[].AliasName' --output text 2>/dev/null | tr '\t' '\n')
      state="$(aws kms describe-key --region "$AWS_REGION" --key-id "$resource_id" \
        --query 'KeyMetadata.KeyState' --output text 2>/dev/null || true)"
      if [[ "$state" != "PendingDeletion" && -n "$state" ]]; then
        try_delete aws kms disable-key --region "$AWS_REGION" --key-id "$resource_id"
        try_delete aws kms schedule-key-deletion --region "$AWS_REGION" \
          --key-id "$resource_id" --pending-window-in-days 7
      fi
      ;;
  esac
}

for _ in 1 2 3 4; do
  mapfile -t candidates < <(list_candidates)
  [[ "${#candidates[@]}" -gt 0 ]] || break

  for resource_kind in listener loadbalancer targetgroup certificate route-table internet-gateway subnet security-group vpc key; do
    for arn in "${candidates[@]}"; do
      [[ "$arn" == *":$resource_kind/"* ]] || continue
      cleanup_arn "$arn"
    done
  done
  sleep 15
done

remaining=0
kms_not_pending=0
mapfile -t candidates < <(list_candidates)
for arn in "${candidates[@]}"; do
  if [[ "$arn" == *":kms:"*":key/"* ]]; then
    state="$(aws kms describe-key --region "$AWS_REGION" --key-id "${arn##*/}" \
      --query 'KeyMetadata.KeyState' --output text 2>/dev/null || true)"
    [[ "$state" == "PendingDeletion" ]] || ((kms_not_pending += 1))
  else
    ((remaining += 1))
  fi
done

jq -n \
  --arg mode "$([[ -n "$RUN_ID_FILTER" ]] && printf targeted || printf expired)" \
  --argjson remaining "$remaining" \
  --argjson kms_not_pending "$kms_not_pending" \
  '{mode:$mode,remaining_resources:$remaining,kms_keys_not_pending_deletion:$kms_not_pending}'

[[ "$remaining" -eq 0 && "$kms_not_pending" -eq 0 ]]
