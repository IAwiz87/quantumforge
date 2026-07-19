package quantumforge.governance

import rego.v1

nonempty_string(value) if {
	is_string(value)
	trim_space(value) != ""
} else := false

valid_timestamp(value) if {
	nonempty_string(value)
	time.parse_rfc3339_ns(value)
} else := false

controls_valid(exception) if {
	controls := object.get(exception, "compensating_controls", null)
	is_array(controls)
	count(controls) > 0
	every control in controls {
		nonempty_string(control)
	}
} else := false

expiration_is_active(exception, assessment_time) if {
	valid_timestamp(object.get(exception, "expires_at", null))
	valid_timestamp(assessment_time)
	time.parse_rfc3339_ns(exception.expires_at) > time.parse_rfc3339_ns(assessment_time)
} else := false

created_at_is_not_future(exception, assessment_time) if {
	valid_timestamp(object.get(exception, "created_at", null))
	valid_timestamp(assessment_time)
	time.parse_rfc3339_ns(exception.created_at) <= time.parse_rfc3339_ns(assessment_time)
} else := false

expiration_follows_creation(exception) if {
	valid_timestamp(object.get(exception, "created_at", null))
	valid_timestamp(object.get(exception, "expires_at", null))
	time.parse_rfc3339_ns(exception.expires_at) > time.parse_rfc3339_ns(exception.created_at)
} else := false

exception_checks(exception, assessment_time) := {
	"id must be a non-empty string": nonempty_string(object.get(exception, "id", null)),
	"asset_id must be a non-empty string": nonempty_string(object.get(exception, "asset_id", null)),
	"owner must be a non-empty string": nonempty_string(object.get(exception, "owner", null)),
	"approver must be a non-empty string": nonempty_string(object.get(exception, "approver", null)),
	"rationale must be a non-empty string": nonempty_string(object.get(exception, "rationale", null)),
	"created_at must be a non-empty string": nonempty_string(object.get(exception, "created_at", null)),
	"expires_at must be a non-empty string": nonempty_string(object.get(exception, "expires_at", null)),
	"compensating_controls must be a non-empty array of non-empty strings": controls_valid(exception),
	"created_at must be RFC3339": valid_timestamp(object.get(exception, "created_at", null)),
	"created_at must not be later than assessment_time": created_at_is_not_future(exception, assessment_time),
	"expires_at must be RFC3339 and later than assessment_time": expiration_is_active(exception, assessment_time),
	"expires_at must be later than created_at": expiration_follows_creation(exception),
	"assessment_time must be RFC3339": valid_timestamp(assessment_time),
}

exception_errors(exception, assessment_time) := {message |
	some message, valid in exception_checks(exception, assessment_time)
	not valid
}

is_valid_exception(exception, assessment_time) if {
	count(exception_errors(exception, assessment_time)) == 0
}

duplicate_exception_ids(exceptions) := duplicates if {
	ids := [id |
		some exception in exceptions
		id := object.get(exception, "id", "")
		nonempty_string(id)
	]
	duplicates := {id |
		some id in ids
		matches := [candidate | some candidate in ids; candidate == id]
		count(matches) > 1
	}
}

active_exceptions contains exception if {
	some exception in input.exceptions
	is_valid_exception(exception, input.assessment_time)
}

invalid_exceptions contains entry if {
	some exception in input.exceptions
	errors := exception_errors(exception, input.assessment_time)
	count(errors) > 0
	entry := {
		"id": object.get(exception, "id", "unknown"),
		"asset_id": object.get(exception, "asset_id", "unknown"),
		"errors": sort(errors),
	}
}

assessment := {
	"active": active_exceptions,
	"invalid": invalid_exceptions,
	"duplicate_ids": duplicate_exception_ids(input.exceptions),
	"active_count": count(active_exceptions),
	"invalid_count": count(invalid_exceptions),
}
