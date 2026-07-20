#!/usr/bin/env bash
set -Eeuo pipefail

PLAN_PATH="${1:?usage: run-census.sh PLAN_JSON OUTPUT_DIR}"
OUTPUT_DIR="${2:?usage: run-census.sh PLAN_JSON OUTPUT_DIR}"
mkdir -p "$OUTPUT_DIR"
STATUS_PATH="$OUTPUT_DIR/assessment-status.json"
CONTEXT_PATH="$OUTPUT_DIR/.plan-context.json"
ASSESSMENT_SCOPE="${QUANTUMFORGE_ASSESSMENT_SCOPE:-environment}"

write_failure_status() {
  local exit_code="$?"
  rm -f "$CONTEXT_PATH"
  jq -n \
    --arg status "collection_failed" \
    --arg assessment_scope "$ASSESSMENT_SCOPE" \
    --arg source "terraform_plan" \
    --arg timestamp "$(date -u +%FT%TZ)" \
    --argjson exit_code "$exit_code" \
    '{status:$status, assessment_scope:$assessment_scope, source:$source, timestamp:$timestamp, exit_code:$exit_code}' \
    > "$STATUS_PATH.tmp"
  mv "$STATUS_PATH.tmp" "$STATUS_PATH"
  exit "$exit_code"
}
trap write_failure_status ERR

[[ "$ASSESSMENT_SCOPE" == "environment" || "$ASSESSMENT_SCOPE" == "synthetic_fixture" ]]
[[ -s "$PLAN_PATH" ]]
jq -e '.resource_changes | type == "array"' "$PLAN_PATH" >/dev/null
jq -e '
  all(.resource_changes[];
    type == "object" and
    (.address | type == "string" and length > 0) and
    (.type | type == "string" and length > 0) and
    (.change | type == "object") and
    (.change.actions | type == "array" and length > 0) and
    (all(.change.actions[]; type == "string" and length > 0)) and
    ((.change.after | type == "object") or
      (.change.after == null and (.change.actions | index("delete")) != null))
  )
' "$PLAN_PATH" >/dev/null
observed_at="$(date -u +%FT%TZ)"
jq --arg observed_at "$observed_at" \
  '. + {"_quantumforge":{"observed_at":$observed_at}}' \
  "$PLAN_PATH" > "$CONTEXT_PATH"

opa eval --fail --format=json \
  --data policies/discovery \
  --input "$CONTEXT_PATH" \
  'data.quantumforge.discovery.normalized_inventory' \
  | jq -e '.result[0].expressions[0].value' \
  > "$OUTPUT_DIR/iac-inventory.json"

opa eval --fail --format=json \
  --data policies/discovery \
  --input "$CONTEXT_PATH" \
  'data.quantumforge.discovery.summary' \
  | jq -e '.result[0].expressions[0].value' \
  > "$OUTPUT_DIR/census-summary.json"

total_assets="$(jq -er '.total_assets' "$OUTPUT_DIR/census-summary.json")"
inventory_assets="$(jq -er '.assets | length' "$OUTPUT_DIR/iac-inventory.json")"
[[ "$inventory_assets" -eq "$total_assets" ]]
if [[ "$total_assets" -eq 0 ]]; then
  status="no_assets_found"
else
  status="assessment_complete"
fi

jq -n \
  --arg status "$status" \
  --arg assessment_scope "$ASSESSMENT_SCOPE" \
  --arg source "terraform_plan" \
  --arg timestamp "$observed_at" \
  --argjson total_assets "$total_assets" \
  '{status:$status, assessment_scope:$assessment_scope, source:$source, timestamp:$timestamp, total_assets:$total_assets}' \
  > "$STATUS_PATH.tmp"
mv "$STATUS_PATH.tmp" "$STATUS_PATH"
rm -f "$CONTEXT_PATH"
trap - ERR
jq . "$STATUS_PATH"
