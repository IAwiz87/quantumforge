terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" # 5.60+ ships ML_DSA_44 / ML_DSA_65 / ML_DSA_87 key_spec support on aws_kms_key
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
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
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
}
