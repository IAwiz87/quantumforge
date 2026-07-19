variable "load_balancer_arn" {
  description = "ARN of an existing Application Load Balancer to attach the hybrid-PQC HTTPS listener to. Network Load Balancers use TLS listeners and are intentionally out of scope for this module."
  type        = string

  validation {
    condition     = can(regex(":elasticloadbalancing:[^:]+:[0-9]{12}:loadbalancer/app/", var.load_balancer_arn))
    error_message = "load_balancer_arn must be an Application Load Balancer ARN containing loadbalancer/app/. Network Load Balancers require a separate TLS listener module."
  }
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate to use for the HTTPS listener."
  type        = string

  validation {
    condition     = can(regex(":acm:[^:]+:[0-9]{12}:certificate/", var.certificate_arn))
    error_message = "certificate_arn must be an ACM certificate ARN."
  }
}

variable "target_group_arn" {
  description = "ARN of the target group that receives traffic from the hybrid-PQC listener."
  type        = string

  validation {
    condition     = can(regex(":elasticloadbalancing:[^:]+:[0-9]{12}:targetgroup/", var.target_group_arn))
    error_message = "target_group_arn must be an ELBv2 target-group ARN."
  }
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
    condition = contains([
      "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
      "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
      "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
      "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
    ], var.ssl_policy)
    error_message = "ssl_policy must be an explicitly approved AWS hybrid post-quantum ALB policy."
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
