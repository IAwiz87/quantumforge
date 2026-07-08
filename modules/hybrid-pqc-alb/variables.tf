variable "load_balancer_arn" {
  description = "ARN of an existing Application or Network Load Balancer to attach the hybrid-PQC listener to."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN presented by the HTTPS listener."
  type        = string
}

variable "target_group_arn" {
  description = "ARN of the target group receiving forwarded traffic."
  type        = string
}

variable "port" {
  description = "Listener port."
  type        = number
  default     = 443
}

variable "ssl_policy" {
  description = "TLS security policy. Defaults to AWS's hybrid post-quantum policy, which negotiates X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 with PQ-capable clients and falls back to classical TLS 1.2/1.3 for others."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"

  validation {
    condition     = endswith(var.ssl_policy, "PQ-2025-09") || endswith(var.ssl_policy, "Res-PQ")
    error_message = "ssl_policy must be a hybrid post-quantum policy (name must contain 'PQ') — this module exists specifically to enforce PQ-capable listeners. Use the aws_lb_listener resource directly for classical-only listeners."
  }
}

variable "additional_certificate_arns" {
  description = "Optional additional certificate ARNs (aws_lb_listener_certificate) for SNI-based multi-cert listeners."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags, including required GRC classification metadata."
  type        = map(string)
  default     = {}
}
