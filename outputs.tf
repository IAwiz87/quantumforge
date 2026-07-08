output "pqc_signing_key_arn" {
  description = "ARN of the provisioned ML-DSA signing key, if enabled."
  value       = try(module.hybrid_pqc_kms[0].key_arn, null)
}

output "pqc_signing_key_alias" {
  description = "Alias of the provisioned ML-DSA signing key, if enabled."
  value       = try(module.hybrid_pqc_kms[0].alias_name, null)
}

output "pqc_alb_listener_arn" {
  description = "ARN of the provisioned hybrid-PQC ALB listener, if enabled."
  value       = try(module.hybrid_pqc_alb[0].listener_arn, null)
}
