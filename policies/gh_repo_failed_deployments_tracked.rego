package compliance_framework.failed_deployments_tracked

failed_deployments := object.get(input, "failed_deployments", [])
deployments := object.get(input, "deployments", [])

title := "Failed deployments are tracked to resolution"
description := "Failed or errored deployments must be followed by a later successful deployment to the same environment, demonstrating that the failure was remediated or rolled back."

risk_templates := [{
  "name": "Unresolved failed deployment observed",
  "title": "Failed Deployment Requires Successful Remediation or Rollback",
  "statement": "Failed or errored deployments indicate release instability or unauthorized change risk. A repository returns to compliance when the failed deployment is followed by a later successful deployment to the same environment, either by redeploying a fixed change or rolling back to a known-good version.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["failed_deployment_unresolved"],
  "remediation": {
    "title": "Resolve the failed deployment with a successful follow-up deployment",
    "description": "Investigate the failed deployment, fix the root cause or roll back, and run a new deployment that records a successful status for the same environment.",
    "tasks": [
      {"title": "Review failed deployment logs and status records"},
      {"title": "Fix the root cause or roll back to a known-good version"},
      {"title": "Run a follow-up deployment to the same environment and verify it completes successfully"}
    ]
  }
}]

violation[{"id": "failed_deployment_unresolved", "remarks": sprintf("Deployment %v failed and has no later successful deployment to the same environment.", [deployment_id])}] if {
  item := failed_deployments[_]
  deployment := object.get(item, "deployment", {})
  deployment_id := object.get(deployment, "id", "unknown")
  not resolved_by_later_success(item)
}

resolved_by_later_success(failed) if {
  candidate := deployments[_]
  same_environment(failed, candidate)
  deployment_succeeded(candidate)
  deployment_after(failed, candidate)
}

same_environment(left, right) if {
  left_deployment := object.get(left, "deployment", {})
  right_deployment := object.get(right, "deployment", {})
  environment := object.get(left_deployment, "environment", "")
  environment != ""
  environment == object.get(right_deployment, "environment", "")
}

deployment_succeeded(item) if {
  status := object.get(item, "statuses", [])[_]
  object.get(status, "state", "") == "success"
}

deployment_after(failed, candidate) if {
  failed_created := deployment_created_ns(failed)
  candidate_created := deployment_created_ns(candidate)
  candidate_created > failed_created
}

deployment_after(failed, candidate) if {
  failed_deployment := object.get(failed, "deployment", {})
  candidate_deployment := object.get(candidate, "deployment", {})
  candidate_id := object.get(candidate_deployment, "id", 0)
  failed_id := object.get(failed_deployment, "id", 0)
  candidate_id > failed_id
}

deployment_created_ns(item) := created_ns if {
  deployment := object.get(item, "deployment", {})
  created_at := object.get(deployment, "created_at", "")
  created_at != ""
  created_ns := time.parse_rfc3339_ns(created_at)
}
