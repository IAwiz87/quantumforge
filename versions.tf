terraform {
  required_version = ">= 1.8.0"


  required_providers {
    aws = {
      source = "hashicorp/aws"
      # ML-DSA support for aws_kms_key landed in 6.1.0. That release was
      # withdrawn; 6.2.0 contains the same feature plus the corrective fix.
      version = "~> 6.2"
    }
  }

  # Configure a remote backend before running this in a real environment.
  # Left commented so `terraform init` succeeds out of the box for local
  # evaluation; uncomment and fill in your own bucket/table before use.
  #
  # backend "s3" {
  #   bucket         = "your-org-tfstate"
  #   key            = "quantumforge/terraform.tfstate"
  #   region         = "us-east-1"
  #   use_lockfile    = true
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
}
