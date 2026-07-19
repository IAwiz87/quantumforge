package quantumforge.inventory

import rego.v1

sample := {
	"assets": [
		{
			"asset_id": "aws:kms:one",
			"provider": "aws",
			"classification": "post_quantum",
			"evidence_confidence": "high",
		},
		{
			"asset_id": "gcp:kms:one",
			"provider": "gcp",
			"classification": "classical_only",
			"evidence_confidence": "high",
		},
		{
			"asset_id": "app:library:one",
			"provider": "application",
			"classification": "unknown",
			"evidence_confidence": "low",
		},
	],
}

test_summary_keeps_unknown_and_confidence_visible if {
	result := summary with input as sample
	result.total_assets == 3
	result.providers.aws == 1
	result.providers.gcp == 1
	result.providers.application == 1
	result.classical_only == 1
	result.unknown == 1
	result.low_confidence == 1
	count(result.inventory_errors) == 0
}

test_migration_candidates_are_deterministic if {
	migration_candidates with input as sample == ["gcp:kms:one"]
}

test_duplicate_asset_ids_are_rejected if {
	duplicated := {"assets": array.concat(sample.assets, [sample.assets[0]])}
	result := inventory_errors with input as duplicated
	"duplicate asset_id: aws:kms:one" in result
}
