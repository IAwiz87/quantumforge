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
  description = "AWS KMS asymmetric key spec. Valid post-quantum values: ML_DSA_44 (NIST L1), ML_DSA_65 (NIST L3), ML_DSA_87 (NIST L5)."
  type        = string
  default     = "ML_DSA_65"

  validation {
    condition     = contains(["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"], var.key_spec)
    error_message = "key_spec must be one of ML_DSA_44, ML_DSA_65, or ML_DSA_87 (FIPS 204 / SP 800-208 post-quantum signature key specs)."
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
  description = "List of IAM ARNs granted key administration permissions (rotation, deletion scheduling, policy edits)."
  type        = list(string)
  default     = []
}

variable "key_users" {
  description = "List of IAM ARNs granted Sign/Verify/DescribeKey/GetPublicKey usage permissions."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags, including required GRC classification metadata."
  type        = map(string)
  default     = {}
}
