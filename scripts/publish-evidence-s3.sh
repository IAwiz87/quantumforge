#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE_PATH="${1:?usage: publish-evidence-s3.sh BUNDLE BUCKET [PREFIX]}"
BUCKET="${2:?usage: publish-evidence-s3.sh BUNDLE BUCKET [PREFIX]}"
PREFIX="${3:-quantumforge}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

[[ -s "$BUNDLE_PATH" ]]
lock_config="$(aws s3api get-object-lock-configuration --region "$AWS_REGION" --bucket "$BUCKET")"
jq -e '.ObjectLockConfiguration.ObjectLockEnabled == "Enabled"' <<<"$lock_config" >/dev/null

retention_ok="$(jq -r '
  .ObjectLockConfiguration.Rule.DefaultRetention as $r |
  (($r.Years // 0) >= 7) or (($r.Days // 0) >= 2555)
' <<<"$lock_config")"
if [[ "$retention_ok" != "true" ]]; then
  echo "Bucket $BUCKET does not have a default Object Lock retention period of at least seven years" >&2
  exit 1
fi

retain_until="$(date -u -d '+7 years' +%Y-%m-%dT%H:%M:%SZ)"
bundle_sha256="$(sha256sum "$BUNDLE_PATH" | awk '{print $1}')"
bundle_checksum_base64="$(openssl dgst -sha256 -binary "$BUNDLE_PATH" | base64 | tr -d '\n')"
key="$PREFIX/$(date -u +%Y/%m/%d)/${GITHUB_REPOSITORY:-local}/${GITHUB_RUN_ID:-local}/$(basename "$BUNDLE_PATH")"

aws s3api put-object \
  --region "$AWS_REGION" \
  --bucket "$BUCKET" \
  --key "$key" \
  --body "$BUNDLE_PATH" \
  --checksum-algorithm SHA256 \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$retain_until" \
  --metadata "sha256=$bundle_sha256,assessment=quantumforge" \
  --content-type application/zip \
  > "${BUNDLE_PATH}.s3-result.json"

version_id="$(jq -er '.VersionId' "${BUNDLE_PATH}.s3-result.json")"
retention_result="$(aws s3api get-object-retention \
  --region "$AWS_REGION" \
  --bucket "$BUCKET" \
  --key "$key" \
  --version-id "$version_id")"
jq -e \
  --arg minimum "$retain_until" \
  '.Retention.Mode == "COMPLIANCE" and .Retention.RetainUntilDate >= $minimum' \
  <<<"$retention_result" >/dev/null

head_result="$(aws s3api head-object \
  --region "$AWS_REGION" \
  --bucket "$BUCKET" \
  --key "$key" \
  --version-id "$version_id" \
  --checksum-mode ENABLED)"
jq -e \
  --arg expected_hex "$bundle_sha256" \
  --arg expected_base64 "$bundle_checksum_base64" \
  '.Metadata.sha256 == $expected_hex and .ChecksumSHA256 == $expected_base64' \
  <<<"$head_result" >/dev/null

jq -n \
  --arg bucket "$BUCKET" \
  --arg key "$key" \
  --arg retain_until "$retain_until" \
  --arg sha256 "$bundle_sha256" \
  --arg version_id "$version_id" \
  '{bucket:$bucket,key:$key,version_id:$version_id,retain_until:$retain_until,sha256:$sha256}'
