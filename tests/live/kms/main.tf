terraform {
  required_version = ">= 1.8.0"

  backend "local" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2"
    }
  }
}

variable "aws_region" {
  type = string
}

variable "run_id" {
  type = string
}

variable "expires_at" {
  type = string
}

provider "aws" {
  region = var.aws_region
}

module "pqc_kms_signing" {
  source = "../../../modules/pqc-kms-signing"

  key_alias               = "quantumforge-live-${var.run_id}"
  description             = "QuantumForge isolated live ML-DSA lifecycle test ${var.run_id}"
  key_spec                = "ML_DSA_65"
  deletion_window_in_days = 7
  tags = {
    project     = "quantumforge"
    environment = "integration-test"
    owner       = "security-engineering"
    test-run    = var.run_id
    expires-at  = var.expires_at
  }
}

output "key_id" {
  value = module.pqc_kms_signing.key_id
}

output "key_arn" {
  value = module.pqc_kms_signing.key_arn
}

output "alias_name" {
  value = module.pqc_kms_signing.alias_name
}

output "key_spec" {
  value = module.pqc_kms_signing.key_spec
}
