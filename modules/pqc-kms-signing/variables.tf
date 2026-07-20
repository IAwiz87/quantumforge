variable "key_alias" {
  description = "Alias suffix for the KMS key (final alias will be alias/<key_alias>)."
  type        = string
}

variable "description" {
  description = "Human-readable description of the key's purpose."
  type        = string
  default     = "QuantumForge post-quantum signing key"
}

variable "key_spec" {
  description = "AWS KMS asymmetric key spec. Valid FIPS 204 values: ML_DSA_44 (NIST security category 2), ML_DSA_65 (category 3), ML_DSA_87 (category 5)."
  type        = string
  default     = "ML_DSA_65"

  validation {
    condition     = contains(["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"], var.key_spec)
    error_message = "key_spec must be one of ML_DSA_44, ML_DSA_65, or ML_DSA_87 (FIPS 204 ML-DSA key specs)."
  }
}


variable "deletion_window_in_days" {
  description = "Waiting period before key deletion is finalized."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "key_administrators" {
  description = "Same-account IAM role/user ARNs granted explicit key administration permissions."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.key_administrators : can(regex("^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:(role|user)/.+$", arn))
    ])
    error_message = "key_administrators entries must be IAM role or user ARNs."
  }
}

variable "key_users" {
  description = "Same-account IAM role/user ARNs granted Sign, Verify, DescribeKey, and GetPublicKey."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.key_users : can(regex("^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:(role|user)/.+$", arn))
    ])
    error_message = "key_users entries must be IAM role or user ARNs."
  }
}

variable "tags" {
  description = "Resource tags, including required GRC classification metadata."
  type        = map(string)
  default     = {}
}

