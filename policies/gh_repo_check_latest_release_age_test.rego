package compliance_framework.change_control_release_recency

test_satisfies_exists if {
  # released 1 day ago
  recent_timestamp := time.format(time.now_ns() - (24 * 60 * 60 * 1000 * 1000 * 1000))
  inp := {"last_release": {"body": "Body with release notes", "published_at": recent_timestamp}}
  violations := { v | violation[v] with input as inp }
  count(violations) == 0
}

test_no_release_violation if {
  inp := {}
  violations := violation[v] with input as inp
  count(violations) == 1
  v.remarks == "No releases available for this repository."
}

test_release_too_old_violation if {
  # released 200 days ago
  recent_timestamp := time.format(time.now_ns() - (200 * 24 * 60 * 60 * 1000 * 1000 * 1000))
  inp := {"last_release": {"body": "Body with release notes", "published_at": recent_timestamp}}
  violations := violation[v] with input as inp
  count(v) == 1
  v.remarks == "Latest Release is too old (older than 90 days)"
}