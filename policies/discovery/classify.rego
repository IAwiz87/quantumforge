# QuantumForge — Phase 1: Discovery & Inventory
#
# Classifies representative AWS cryptographic resources from Terraform plan
# JSON. Every entry is normalized enough to map into schemas/crypto-inventory.schema.json.
# Unsupported and provider-managed values remain "unknown" rather than being
# counted as clean.

package quantumforge.discovery

import rego.v1

classical_key_specs := {
	"RSA_2048", "RSA_3072", "RSA_4096",
	"ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1",
	"EC_prime256v1", "EC_secp384r1",
}

post_quantum_key_specs := {"ML_DSA_44", "ML_DSA_65", "ML_DSA_87"}

approved_hybrid_tls_policies := {
	"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}

first_object(value) := value if is_object(value)
else := value[0] if {
	is_array(value)
	count(value) > 0
	is_object(value[0])
}
else := {}

classify_key_spec(spec) := "post_quantum" if spec in post_quantum_key_specs
else := "classical_only" if spec in classical_key_specs
else := "symmetric" if spec == "SYMMETRIC_DEFAULT"
else := "unknown"

classify_tls_policy(policy) := "hybrid_post_quantum" if policy in approved_hybrid_tls_policies
else := "classical_only" if {
	is_string(policy)
	policy != ""
}
else := "unknown"

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_kms_key"
	after := object.get(rc.change, "after", null)
	is_object(after)
	spec := object.get(after, "customer_master_key_spec", "unknown")
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": object.get(after, "key_usage", "unknown"),
		"algorithm": spec,
		"classification": classify_key_spec(spec),
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_lb_listener"
	after := object.get(rc.change, "after", null)
	is_object(after)
	protocol := object.get(after, "protocol", "unknown")
	protocol in {"HTTPS", "TLS"}
	policy := object.get(after, "ssl_policy", "unknown")
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "tls_termination",
		"protocol": protocol,
		"algorithm": policy,
		"classification": classify_tls_policy(policy),
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_acm_certificate"
	after := object.get(rc.change, "after", null)
	is_object(after)
	algorithm := object.get(after, "key_algorithm", "unknown")
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "certificate",
		"algorithm": algorithm,
		"classification": classify_key_spec(algorithm),
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_acmpca_certificate_authority"
	after := object.get(rc.change, "after", null)
	is_object(after)
	algorithm := object.get(after, "key_algorithm", "unknown")
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "certificate_authority",
		"algorithm": algorithm,
		"classification": classify_key_spec(algorithm),
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_cloudfront_distribution"
	after := object.get(rc.change, "after", null)
	is_object(after)
	viewer := first_object(object.get(after, "viewer_certificate", {}))
	minimum_protocol := object.get(viewer, "minimum_protocol_version", "unknown")
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "tls_termination",
		"protocol": minimum_protocol,
		"algorithm": "provider_managed",
		"classification": "unknown",
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type in {"aws_api_gateway_domain_name", "aws_apigatewayv2_domain_name"}
	after := object.get(rc.change, "after", null)
	is_object(after)
	configuration := first_object(object.get(after, "domain_name_configuration", after))
	security_policy := object.get(configuration, "security_policy", object.get(after, "security_policy", "unknown"))
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "tls_termination",
		"protocol": security_policy,
		"algorithm": "provider_managed",
		"classification": "unknown",
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

inventory contains entry if {
	some rc in object.get(input, "resource_changes", [])
	rc.type == "aws_vpn_connection"
	after := object.get(rc.change, "after", null)
	is_object(after)
	entry := {
		"asset_id": rc.address,
		"address": rc.address,
		"provider": "aws",
		"resource_type": rc.type,
		"type": rc.type,
		"crypto_function": "network_encryption",
		"protocol": "IPsec/IKE",
		"algorithm": "provider_or_tunnel_configured",
		"classification": "unknown",
		"source": "terraform_plan",
		"metadata": {"tags": object.get(after, "tags", {})},
	}
}

nonempty(value) if {
	is_string(value)
	trim_space(value) != ""
} else := false

string_or_unknown(value) := value if nonempty(value)
else := "unknown"

entry_tags(entry) := tags if {
	metadata := object.get(entry, "metadata", {})
	is_object(metadata)
	tags := object.get(metadata, "tags", {})
	is_object(tags)
} else := {}

normalized_owner(entry) := value if {
	value := object.get(entry_tags(entry), "owner", "")
	nonempty(value)
} else := value if {
	value := object.get(entry_tags(entry), "Owner", "")
	nonempty(value)
} else := "unassigned"

normalized_environment(entry) := value if {
	value := object.get(entry_tags(entry), "environment", "")
	nonempty(value)
} else := value if {
	value := object.get(entry_tags(entry), "Environment", "")
	nonempty(value)
} else := "unknown"

normalized_crypto_function(entry) := "signing" if {
	entry.resource_type == "aws_kms_key"
	entry.crypto_function == "SIGN_VERIFY"
} else := "key_management" if {
	entry.resource_type == "aws_kms_key"
} else := value if {
	value := object.get(entry, "crypto_function", "other")
	value in {
		"key_management", "signing", "encryption_at_rest", "tls_termination",
		"network_encryption", "certificate", "certificate_authority", "library",
		"protocol", "other",
	}
} else := "other"

observation_time := value if {
	context := object.get(input, "_quantumforge", {})
	is_object(context)
	value := object.get(context, "observed_at", "")
	nonempty(value)
} else := "1970-01-01T00:00:00Z"

normalized_confidence(entry) := "low" if entry.classification == "unknown"
else := "high"

normalized_assets contains asset if {
	some entry in inventory
	asset := {
		"asset_id": entry.asset_id,
		"provider": entry.provider,
		"resource_type": entry.resource_type,
		"crypto_function": normalized_crypto_function(entry),
		"algorithm": string_or_unknown(object.get(entry, "algorithm", "unknown")),
		"protocol": string_or_unknown(object.get(entry, "protocol", "unknown")),
		"classification": entry.classification,
		"owner": normalized_owner(entry),
		"environment": normalized_environment(entry),
		"source": entry.source,
		"observed_at": observation_time,
		"evidence_confidence": normalized_confidence(entry),
		"metadata": {
			"terraform_address": entry.address,
			"terraform_type": entry.type,
			"tags": entry_tags(entry),
		},
	}
}

normalized_inventory := {
	"schema_version": "1.0.0",
	"assets": normalized_assets,
}

pqc_ready_classifications := {"post_quantum", "hybrid_post_quantum"}

summary := {
	"total_assets": count(inventory),
	"post_quantum_ready": count([e | some e in inventory; e.classification in pqc_ready_classifications]),
	"classical_only": count([e | some e in inventory; e.classification == "classical_only"]),
	"symmetric": count([e | some e in inventory; e.classification == "symmetric"]),
	"unknown": count([e | some e in inventory; e.classification == "unknown"]),
}
