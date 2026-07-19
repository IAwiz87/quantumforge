# QuantumForge — pqc-kms-signing
#
# Provisions an AWS KMS asymmetric signing key using a NIST FIPS 204 (ML-DSA)
# post-quantum key spec. This is pure ML-DSA signing, not a classical/PQC
# hybrid signature construction. Keys are generated and protected inside FIPS 140-3
# Security Level 3 validated HSMs by AWS KMS.
#
# Reference: https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}


locals {
  key_admin_statement = length(var.key_administrators) > 0 ? [{
    Sid    = "AllowKeyAdministration"
    Effect = "Allow"
    Principal = {
      AWS = var.key_administrators
    }
    Action = [
      "kms:CancelKeyDeletion",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:GetKeyPolicy",
      "kms:ListGrants",
      "kms:ListKeyPolicies",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:RevokeGrant",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateKeyDescription",
    ]
    Resource = "*"
  }] : []

  key_user_statement = length(var.key_users) > 0 ? [{
    Sid    = "AllowKeyUsage"
    Effect = "Allow"
    Principal = {
      AWS = var.key_users
    }
    Action = [
      "kms:DescribeKey",
      "kms:GetPublicKey",
      "kms:Sign",
      "kms:Verify",
    ]
    Resource = "*"
  }] : []

  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }],
      local.key_admin_statement,
      local.key_user_statement,
    )
  })
}

resource "aws_kms_key" "pqc_signing" {
  description              = var.description
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = var.key_spec
  deletion_window_in_days  = var.deletion_window_in_days

  # Asymmetric keys (including ML-DSA) do not support AWS-managed automatic
  # rotation — key rotation for signing keys must be handled operationally
  # (issue a new key, dual-sign/verify during transition, retire the old key).
  enable_key_rotation = false

  policy = local.key_policy

  lifecycle {
    precondition {
      condition = alltrue([
        for arn in concat(var.key_administrators, var.key_users) :
        startswith(arn, "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/") ||
        startswith(arn, "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/")
      ])
      error_message = "key_administrators and key_users must belong to the current AWS account."
    }
  }

  tags = merge(var.tags, {
    "quantumforge:algorithm-family" = "post-quantum"
    "quantumforge:standard"         = "FIPS-204-ML-DSA"
    "quantumforge:managed-by"       = "quantumforge-pqc-grc-framework"
  })
}

resource "aws_kms_alias" "pqc_signing" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.pqc_signing.key_id
}
