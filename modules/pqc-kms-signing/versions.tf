terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2" # 6.2+ supports ML_DSA_44 / ML_DSA_65 / ML_DSA_87 on aws_kms_key
    }
  }
}

