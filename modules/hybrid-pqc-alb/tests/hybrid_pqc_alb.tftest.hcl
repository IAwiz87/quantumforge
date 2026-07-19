mock_provider "aws" {}

run "hybrid_pq_https_listener" {
  command = plan

  variables {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/quantumforge/0000000000000000"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/quantumforge/0000000000000000"
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition     = aws_lb_listener.hybrid_pqc_https.protocol == "HTTPS"
    error_message = "The ALB module must create an HTTPS listener."
  }

  assert {
    condition     = aws_lb_listener.hybrid_pqc_https.ssl_policy == "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
    error_message = "The listener must use the approved hybrid PQ-TLS policy by default."
  }

  assert {
    condition     = aws_lb_listener.hybrid_pqc_https.port == 443
    error_message = "The listener must default to port 443."
  }
}

run "allow_fips_hybrid_policy" {
  command = plan

  variables {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/quantumforge/0000000000000000"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/quantumforge/0000000000000000"
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
    ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09"
  }
}

run "reject_unapproved_policy" {
  command = plan

  variables {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/1234567890abcdef"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/1234567890abcdef"
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-EVIL"
  }

  expect_failures = [var.ssl_policy]
}

run "reject_network_load_balancer_arn" {
  command = plan

  variables {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/example/1234567890abcdef"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/1234567890abcdef"
    certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
  }

  expect_failures = [var.load_balancer_arn]
}

run "reject_malformed_certificate_arn" {
  command = plan

  variables {
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/1234567890abcdef"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/1234567890abcdef"
    certificate_arn   = "not-an-acm-arn"
  }

  expect_failures = [var.certificate_arn]
}
