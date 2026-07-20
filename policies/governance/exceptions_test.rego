package quantumforge.governance

import rego.v1

assessment_time := "2026-07-19T12:00:00Z"

active_exception := {
	"id": "QF-EX-001",
	"asset_id": "aws_lb_listener.legacy",
	"owner": "payments-platform",
	"approver": "security-governance",
	"rationale": "A client dependency cannot negotiate PQ-TLS yet.",
	"compensating_controls": ["TLS 1.3 required", "Restricted source CIDRs"],
	"created_at": "2026-07-01T12:00:00Z",
	"expires_at": "2026-08-01T12:00:00Z",
}

test_active_exception_is_valid if {
	is_valid_exception(active_exception, assessment_time)
	count(exception_errors(active_exception, assessment_time)) == 0
}

test_expired_exception_fails_closed if {
	expired := object.union(active_exception, {"expires_at": "2026-07-01T12:00:00Z"})
	"expires_at must be RFC3339 and later than assessment_time" in exception_errors(expired, assessment_time)
	not is_valid_exception(expired, assessment_time)
}

test_missing_owner_and_controls_are_rejected if {
	invalid := object.remove(active_exception, {"owner", "compensating_controls"})
	errors := exception_errors(invalid, assessment_time)
	"owner must be a non-empty string" in errors
	"compensating_controls must be a non-empty array of non-empty strings" in errors
}

test_malformed_timestamp_is_rejected if {
	invalid := object.union(active_exception, {"expires_at": "next Friday"})
	"expires_at must be RFC3339 and later than assessment_time" in exception_errors(invalid, assessment_time)
}

test_future_created_at_is_rejected if {
	invalid := object.union(active_exception, {"created_at": "2026-07-20T12:00:00Z"})
	"created_at must not be later than assessment_time" in exception_errors(invalid, assessment_time)
	not is_valid_exception(invalid, assessment_time)
}

test_expiration_before_creation_is_rejected if {
	invalid := object.union(active_exception, {
		"created_at": "2026-07-10T12:00:00Z",
		"expires_at": "2026-07-05T12:00:00Z",
	})
	"expires_at must be later than created_at" in exception_errors(invalid, assessment_time)
	not is_valid_exception(invalid, assessment_time)
}

test_batch_assessment_reports_invalid_records if {
	batch := {
		"assessment_time": assessment_time,
		"exceptions": [
			active_exception,
			object.union(active_exception, {
				"id": "QF-EX-002",
				"expires_at": "2026-07-01T12:00:00Z",
			}),
		],
	}
	result := assessment with input as batch
	result.active_count == 1
	result.invalid_count == 1
}

test_duplicate_exception_ids_are_reported if {
	duplicate := object.union(active_exception, {"asset_id": "aws_kms_key.legacy"})
	result := assessment with input as {
		"assessment_time": assessment_time,
		"exceptions": [active_exception, duplicate],
	}
	result.duplicate_ids == {"QF-EX-001"}
}
