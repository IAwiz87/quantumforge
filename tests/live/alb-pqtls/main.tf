terraform {
  required_version = ">= 1.8.0"

  backend "local" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2"
    }
  }
}

variable "aws_region" {
  type = string
}

variable "run_id" {
  type = string
}

variable "expires_at" {
  type = string
}

variable "certificate_arn" {
  type = string
}

provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  short_id = substr(replace(lower(var.run_id), "_", "-"), 0, 12)
  common_tags = {
    project     = "quantumforge"
    environment = "integration-test"
    owner       = "security-engineering"
    test-run    = var.run_id
    expires-at  = var.expires_at
  }
}

resource "aws_vpc" "test" {
  #checkov:skip=CKV2_AWS_11:A short-lived handshake fixture has no workloads or application traffic; the test captures TLS evidence and destroys the VPC.
  #checkov:skip=CKV2_AWS_12:The default security group is unused; mutating it would require broader untagged-resource IAM permissions.
  cidr_block           = "10.255.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.common_tags, { Name = "qf-pqtls-${local.short_id}" })
}


resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags   = local.common_tags
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.test.id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  cidr_block              = cidrsubnet(aws_vpc.test.cidr_block, 8, count.index)
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "qf-pqtls-${local.short_id}-${count.index}" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id
  tags   = local.common_tags
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.test.id
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  #checkov:skip=CKV_AWS_260:Public TCP/443 is the behavior under test; there are no registered targets and cleanup is automatic.
  name_prefix = "qf-pqtls-${local.short_id}-"
  description = "Ephemeral QuantumForge PQ-TLS handshake test"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "Ephemeral public TLS handshake test"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

#tfsec:ignore:aws-elb-alb-not-public -- This isolated fixture must be internet-facing so the external runtime client can prove TLS negotiation.
resource "aws_lb" "test" {
  #checkov:skip=CKV_AWS_91:Access logs are omitted for a short-lived handshake-only fixture; OpenSSL transcripts are the test evidence.
  #checkov:skip=CKV_AWS_150:Deletion protection must be disabled so the cleanup trap can remove this paid resource.
  #checkov:skip=CKV2_AWS_28:WAF is out of scope for a TLS handshake fixture with no registered application targets.
  name                       = "qf-pqtls-${local.short_id}"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  enable_deletion_protection = false
  tags                       = local.common_tags
}

resource "aws_lb_target_group" "empty" {
  name        = "qf-pqtls-${local.short_id}"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.test.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    path                = "/"
    protocol            = "HTTP"
    timeout             = 5
  }

  tags = local.common_tags
}

module "hybrid_pqc_alb" {
  source = "../../../modules/hybrid-pqc-alb"

  load_balancer_arn = aws_lb.test.arn
  target_group_arn  = aws_lb_target_group.empty.arn
  certificate_arn   = var.certificate_arn
  tags              = local.common_tags
}

output "load_balancer_arn" {
  value = aws_lb.test.arn
}

output "dns_name" {
  value = aws_lb.test.dns_name
}

output "listener_arn" {
  value = module.hybrid_pqc_alb.listener_arn
}

output "ssl_policy" {
  value = module.hybrid_pqc_alb.ssl_policy
}
