# QuantumForge — hybrid-pqc-alb
#
# Provisions an Application Load Balancer HTTPS listener using AWS's hybrid
# post-quantum TLS security
# policy (ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09), which offers
# X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 hybrid key
# exchange to PQ-capable clients while gracefully falling back to classical
# TLS 1.2/1.3 for clients that don't yet support ML-KEM.
#
# Network Load Balancers use protocol TLS and are intentionally outside this
# module's contract.
# Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html

resource "aws_lb_listener" "hybrid_pqc_https" {
  load_balancer_arn = var.load_balancer_arn
  port              = var.port
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.target_group_arn
  }

  tags = merge(var.tags, {
    "quantumforge:tls-policy" = "hybrid-post-quantum"
    "quantumforge:managed-by" = "quantumforge-pqc-grc-framework"
  })
}

resource "aws_lb_listener_certificate" "additional" {
  for_each        = toset(var.additional_certificate_arns)
  listener_arn    = aws_lb_listener.hybrid_pqc_https.arn
  certificate_arn = each.value
}
