terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" # 5.60+ ships ML_DSA_44 / ML_DSA_65 / ML_DSA_87 key_spec support
    }
  }
}
