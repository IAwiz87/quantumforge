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

run "deployment_is_opt_in" {
  command = plan

  assert {
    condition     = output.pqc_signing_key_arn == null
    error_message = "The root module must not create a KMS key unless explicitly enabled."
  }

  assert {
    condition     = output.pqc_alb_listener_arn == null
    error_message = "The root module must not create an ALB listener unless explicitly enabled."
  }
}

run "enable_pqc_signing" {
  command = plan

  variables {
    enable_pqc_kms_signing = true
    environment            = "ci-test"
  }

  assert {
    condition     = module.pqc_kms_signing[0].key_spec == "ML_DSA_65"
    error_message = "Enabling PQC signing must plan an ML_DSA_65 key."
  }

  assert {
    condition     = module.pqc_kms_signing[0].signing_algorithm == "ML_DSA_SHAKE_256"
    error_message = "The root module must expose the ML-DSA signing algorithm."
  }
}
