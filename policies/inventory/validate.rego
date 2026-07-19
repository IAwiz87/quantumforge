package quantumforge.inventory

import rego.v1

assets := object.get(input, "assets", [])

asset_ids := [asset.asset_id | some asset in assets]

duplicate_asset_ids contains asset_id if {
	some asset_id in asset_ids
	count([candidate | some candidate in asset_ids; candidate == asset_id]) > 1
}

inventory_errors contains sprintf("duplicate asset_id: %s", [asset_id]) if {
	some asset_id in duplicate_asset_ids
}

migration_candidates := sort([asset.asset_id |
	some asset in assets
	asset.classification == "classical_only"
])

unknown_assets := sort([asset.asset_id |
	some asset in assets
	asset.classification == "unknown"
])

summary := {
	"total_assets": count(assets),
	"providers": {provider: count([asset | some asset in assets; asset.provider == provider]) |
		some provider in {asset.provider | some asset in assets}
	},
	"classical_only": count(migration_candidates),
	"unknown": count(unknown_assets),
	"low_confidence": count([asset | some asset in assets; asset.evidence_confidence == "low"]),
	"inventory_errors": inventory_errors,
}
