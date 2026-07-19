#!/usr/bin/env bash
set -Eeuo pipefail

PLAN_PATH="${1:?usage: run-census.sh PLAN_JSON OUTPUT_DIR}"
OUTPUT_DIR="${2:?usage: run-census.sh PLAN_JSON OUTPUT_DIR}"
mkdir -p "$OUTPUT_DIR"
STATUS_PATH="$OUTPUT_DIR/assessment-status.json"

write_failure_status() {
  local exit_code="$?"
  jq -n \
    --arg status "collection_failed" \
    --arg source "$PLAN_PATH" \
    --arg timestamp "$(date -u +%FT%TZ)" \
    --argjson exit_code "$exit_code" \
    '{status:$status, source:$source, timestamp:$timestamp, exit_code:$exit_code}' \
    > "$STATUS_PATH.tmp"
  mv "$STATUS_PATH.tmp" "$STATUS_PATH"
  exit "$exit_code"
}
trap write_failure_status ERR

[[ -s "$PLAN_PATH" ]]
jq -e '.resource_changes | type == "array"' "$PLAN_PATH" >/dev/null

opa eval --fail --format=json \
  --data policies/discovery \
  --input "$PLAN_PATH" \
  'data.quantumforge.discovery.inventory' \
  | jq -e '.result[0].expressions[0].value' \
  > "$OUTPUT_DIR/iac-inventory.json"

opa eval --fail --format=json \
  --data policies/discovery \
  --input "$PLAN_PATH" \
  'data.quantumforge.discovery.summary' \
  | jq -e '.result[0].expressions[0].value' \
  > "$OUTPUT_DIR/census-summary.json"

total_assets="$(jq -er '.total_assets' "$OUTPUT_DIR/census-summary.json")"
if [[ "$total_assets" -eq 0 ]]; then
  status="no_assets_found"
else
  status="assessment_complete"
fi

jq -n \
  --arg status "$status" \
  --arg source "$PLAN_PATH" \
  --arg timestamp "$(date -u +%FT%TZ)" \
  --argjson total_assets "$total_assets" \
  '{status:$status, source:$source, timestamp:$timestamp, total_assets:$total_assets}' \
  > "$STATUS_PATH.tmp"
mv "$STATUS_PATH.tmp" "$STATUS_PATH"
trap - ERR
jq . "$STATUS_PATH"
