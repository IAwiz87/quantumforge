mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
}

run "ml_dsa_65_defaults" {
  command = plan

  variables {
    key_alias = "quantumforge-test-signing"
    tags = {
      environment = "test"
      owner       = "security-engineering"
    }
  }

  assert {
    condition     = aws_kms_key.pqc_signing.key_usage == "SIGN_VERIFY"
    error_message = "The PQC signing key must be restricted to SIGN_VERIFY."
  }

  assert {
    condition     = aws_kms_key.pqc_signing.customer_master_key_spec == "ML_DSA_65"
    error_message = "The default KMS key spec must be ML_DSA_65."
  }

  assert {
    condition     = aws_kms_key.pqc_signing.enable_key_rotation == false
    error_message = "Automatic rotation is unsupported for asymmetric KMS signing keys."
  }

  assert {
    condition     = aws_kms_key.pqc_signing.deletion_window_in_days == 30
    error_message = "The default deletion window must remain 30 days."
  }

  assert {
    condition     = output.signing_algorithm == "ML_DSA_SHAKE_256"
    error_message = "The module must expose the AWS ML-DSA signing algorithm."
  }
}

run "reject_classical_key_spec" {
  command = plan

  variables {
    key_alias = "quantumforge-invalid-signing"
    key_spec  = "RSA_4096"
  }

  expect_failures = [var.key_spec]
}

run "reject_short_deletion_window" {
  command = plan

  variables {
    key_alias               = "quantumforge-invalid-deletion"
    deletion_window_in_days = 6
  }

  expect_failures = [var.deletion_window_in_days]
}

run "allow_same_account_role_principals" {
  command = plan

  variables {
    key_alias          = "quantumforge-principals"
    key_administrators = ["arn:aws:iam::123456789012:role/quantumforge-admin"]
    key_users          = ["arn:aws:iam::123456789012:role/quantumforge-signer"]
  }

  assert {
    condition     = strcontains(aws_kms_key.pqc_signing.policy, "quantumforge-signer")
    error_message = "The explicit same-account key user must be present in the key policy."
  }
}

run "reject_non_iam_principal" {
  command = plan

  variables {
    key_alias = "quantumforge-invalid-principal"
    key_users = ["not-an-iam-arn"]
  }

  expect_failures = [var.key_users]
}

run "reject_cross_account_principal" {
  command = plan

  variables {
    key_alias = "quantumforge-cross-account"
    key_users = ["arn:aws:iam::210987654321:role/external-signer"]
  }

  expect_failures = [aws_kms_key.pqc_signing]
}
