# QuantumForge
# Root module wiring the hybrid-PQC reference modules together.
#
# This root module is intentionally conditional (enable_* flags) so it can
# be `terraform validate`'d and `terraform plan`'d with zero required inputs
# in CI, while still being usable as a real deployable root for a sandbox
# or production account by supplying the existing_* variables.


module "hybrid_pqc_kms" {
  count  = var.enable_hybrid_pqc_kms ? 1 : 0
  source = "./modules/hybrid-pqc-kms"

  key_alias   = "quantumforge-${var.environment}-signing"
  description = "QuantumForge ${var.environment} ML-DSA post-quantum signing key"
  key_spec    = "ML_DSA_65"
  tags        = var.tags
}

module "hybrid_pqc_alb" {
  count  = var.enable_hybrid_pqc_alb ? 1 : 0
  source = "./modules/hybrid-pqc-alb"

  load_balancer_arn = var.existing_load_balancer_arn
  target_group_arn  = var.existing_target_group_arn
  certificate_arn   = var.existing_acm_certificate_arn
  tags              = var.tags
}

