variable "aws_region" {
  description = "AWS region to provision QuantumForge reference infrastructure in."
  type        = string
  default     = "us-east-1"
}


variable "environment" {
  description = "Environment name used in tags and naming (e.g. sandbox, staging, prod)."
  type        = string
  default     = "sandbox"
}

variable "enable_pqc_kms_signing" {
  description = "Whether to provision the reference ML-DSA KMS signing key."
  type        = bool
  default     = false
}

variable "enable_hybrid_pqc_alb" {
  description = "Whether to provision the reference hybrid-PQC ALB listener. Requires an existing load balancer, target group, and ACM certificate."
  type        = bool
  default     = false
}

variable "existing_load_balancer_arn" {
  description = "ARN of an existing Application Load Balancer to attach the hybrid-PQC HTTPS listener to (required if enable_hybrid_pqc_alb = true)."
  type        = string
  default     = ""
}

variable "existing_target_group_arn" {
  description = "ARN of an existing target group (required if enable_hybrid_pqc_alb = true)."
  type        = string
  default     = ""
}

variable "existing_acm_certificate_arn" {
  description = "ARN of an existing ACM certificate (required if enable_hybrid_pqc_alb = true)."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags applied to all QuantumForge-managed resources."
  type        = map(string)
  default = {
    "project" = "quantumforge-pqc-grc-framework"
  }
}
