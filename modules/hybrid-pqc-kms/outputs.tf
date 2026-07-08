output "key_id" {
  description = "The globally unique identifier for the KMS key."
  value       = aws_kms_key.pqc_signing.key_id
}

output "key_arn" {
  description = "The Amazon Resource Name (ARN) of the KMS key."
  value       = aws_kms_key.pqc_signing.arn
}

output "alias_name" {
  description = "The alias assigned to the key."
  value       = aws_kms_alias.pqc_signing.name
}

output "key_spec" {
  description = "The post-quantum key spec provisioned (ML_DSA_44 / ML_DSA_65 / ML_DSA_87)."
  value       = aws_kms_key.pqc_signing.customer_master_key_spec
}

output "signing_algorithm" {
  description = "The AWS KMS signing algorithm to use with this key (fixed for all ML-DSA key specs)."
  value       = "ML_DSA_SHAKE_256"
}
