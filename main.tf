# QuantumForge
# Root module wiring the PQC reference modules together.
#
# Deployable resources are opt-in. Pull-request CI exercises them with
# Terraform's native mock provider; live plans run only in an authenticated
# sandbox integration workflow.

module "pqc_kms_signing" {
  count  = var.enable_pqc_kms_signing ? 1 : 0
  source = "./modules/pqc-kms-signing"

  key_alias   = "quantumforge-${var.environment}-signing"
  description = "QuantumForge ${var.environment} ML-DSA post-quantum signing key"
  key_spec    = "ML_DSA_65"
  tags        = var.tags
}

moved {
  from = module.hybrid_pqc_kms[0]
  to   = module.pqc_kms_signing[0]
}

module "hybrid_pqc_alb" {
  count  = var.enable_hybrid_pqc_alb ? 1 : 0
  source = "./modules/hybrid-pqc-alb"

  load_balancer_arn = var.existing_load_balancer_arn
  target_group_arn  = var.existing_target_group_arn
  certificate_arn   = var.existing_acm_certificate_arn
  tags              = var.tags
}

