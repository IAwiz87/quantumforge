output "listener_arn" {
  description = "ARN of the hybrid-PQC HTTPS listener."
  value       = aws_lb_listener.hybrid_pqc_https.arn
}

output "ssl_policy" {
  description = "The TLS security policy applied to the listener."
  value       = aws_lb_listener.hybrid_pqc_https.ssl_policy
}

output "supported_hybrid_groups" {
  description = "Hybrid key-exchange groups negotiable under this policy (informational)."
  value       = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
}
