"""Test cases for evaluating Dependabot alert analysis agents.

Cases cover the major failure modes:
- Wrong tool selection (agent doesn't fetch alerts before triaging)
- Hallucinated severity (agent invents CVSS scores or advisory IDs)
- Missed critical alerts (agent skips high-severity items)
- Wrong remediation (agent recommends downgrade or nonexistent version)
- Scope confusion (agent treats devDependency as runtime-critical)
"""

from strands_evals import Case

# --- Triage agent cases ---

TRIAGE_CASES: list[Case] = [
    Case(
        name="triage-single-repo-critical",
        input="Triage all open Dependabot alerts for owner=strands-agents repo=sdk",
        expected_output=None,  # evaluated by rubric, not exact match
        expected_trajectory=[
            "fetch_dependabot_alerts",  # must fetch alerts first
        ],
        metadata={"category": "triage", "expected_tools": ["fetch_dependabot_alerts"]},
    ),
    Case(
        name="triage-org-wide",
        input="List all repos with critical Dependabot alerts in the strands-agents org",
        expected_output=None,
        expected_trajectory=[
            "list_repos_with_alerts",
        ],
        metadata={"category": "triage", "expected_tools": ["list_repos_with_alerts"]},
    ),
    Case(
        name="triage-deep-dive-alert",
        input=(
            "Get full details on alert #42 in strands-agents/sdk and assess its urgency. "
            "The alert is for a critical RCE in a runtime dependency."
        ),
        expected_output=None,
        expected_trajectory=[
            "get_alert_detail",
        ],
        metadata={
            "category": "triage",
            "failure_mode_target": "hallucination",
            "note": "Agent must use tool, not fabricate advisory details",
        },
    ),
    Case(
        name="triage-dev-dependency-scope",
        input=(
            "Triage alerts for owner=myorg repo=frontend. "
            "Pay special attention to whether vulnerable packages are runtime or dev dependencies."
        ),
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
        ],
        metadata={
            "category": "triage",
            "failure_mode_target": "scope_confusion",
            "note": "Agent should differentiate runtime vs dev scope in urgency",
        },
    ),
    Case(
        name="triage-no-alerts",
        input="Triage Dependabot alerts for owner=healthy-org repo=clean-repo",
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
        ],
        metadata={
            "category": "triage",
            "failure_mode_target": "hallucination",
            "note": "Agent should report zero alerts, not invent them",
        },
    ),
]

# --- Remediation agent cases ---

REMEDIATION_CASES: list[Case] = [
    Case(
        name="remediation-patched-available",
        input=(
            "Create a remediation plan for alert #10 in strands-agents/sdk. "
            "The alert is for lodash with a known patched version."
        ),
        expected_output=None,
        expected_trajectory=[
            "check_fix_available",
            "get_upgrade_path",
        ],
        metadata={
            "category": "remediation",
            "expected_tools": ["check_fix_available", "get_upgrade_path"],
        },
    ),
    Case(
        name="remediation-no-fix",
        input=(
            "Create a remediation plan for alert #99 in myorg/legacy-app. "
            "There is no patched version available yet."
        ),
        expected_output=None,
        expected_trajectory=[
            "check_fix_available",
        ],
        metadata={
            "category": "remediation",
            "failure_mode_target": "wrong_remediation",
            "note": "Agent should recommend mitigation, not a nonexistent upgrade",
        },
    ),
    Case(
        name="remediation-major-version-bump",
        input=(
            "Assess remediation for alert #5 in myorg/api-service. "
            "The fix requires upgrading from v2.x to v4.x of the package."
        ),
        expected_output=None,
        expected_trajectory=[
            "check_fix_available",
            "get_upgrade_path",
        ],
        metadata={
            "category": "remediation",
            "failure_mode_target": "breaking_change_risk",
            "note": "Agent must flag high breaking change risk for major bump",
        },
    ),
    Case(
        name="remediation-advisory-lookup",
        input=(
            "Look up advisory GHSA-1234-5678-abcd and create a remediation plan "
            "for all affected packages in myorg/data-pipeline."
        ),
        expected_output=None,
        expected_trajectory=[
            "get_advisory_detail",
            "check_fix_available",
        ],
        metadata={
            "category": "remediation",
            "expected_tools": ["get_advisory_detail", "check_fix_available"],
        },
    ),
]


# --- Reporting agent cases ---

REPORTING_CASES: list[Case] = [
    Case(
        name="report-single-repo",
        input="Generate a vulnerability report for owner=strands-agents repo=sdk",
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
            "aggregate_alert_stats",
            "build_executive_summary",
        ],
        metadata={
            "category": "reporting",
            "expected_tools": [
                "fetch_dependabot_alerts",
                "aggregate_alert_stats",
                "build_executive_summary",
            ],
        },
    ),
    Case(
        name="report-org-wide-with-teams",
        input=(
            "Generate an org-wide vulnerability report for strands-agents "
            "with team assignments. Use default ecosystem-to-team mapping."
        ),
        expected_output=None,
        expected_trajectory=[
            "list_repos_with_alerts",
            "fetch_dependabot_alerts",
            "aggregate_alert_stats",
            "generate_team_assignments",
            "build_executive_summary",
        ],
        metadata={
            "category": "reporting",
            "expected_tools": [
                "list_repos_with_alerts",
                "aggregate_alert_stats",
                "generate_team_assignments",
            ],
        },
    ),
    Case(
        name="report-empty-repo",
        input="Generate a vulnerability report for owner=healthy-org repo=clean-repo",
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
        ],
        metadata={
            "category": "reporting",
            "failure_mode_target": "hallucination",
            "note": "Agent should report zero alerts, not fabricate statistics",
        },
    ),
    Case(
        name="report-stats-accuracy",
        input=(
            "Generate a report for owner=myorg repo=data-pipeline. "
            "Make sure severity counts and fix-available percentages are exact."
        ),
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
            "aggregate_alert_stats",
        ],
        metadata={
            "category": "reporting",
            "failure_mode_target": "stats_fabrication",
            "note": "Agent must not round or estimate — use tool output verbatim",
        },
    ),
    Case(
        name="report-api-failure-handling",
        input=(
            "Generate a vulnerability report for owner=private-org repo=secret-repo. "
            "You may not have access to this repository."
        ),
        expected_output=None,
        expected_trajectory=[
            "fetch_dependabot_alerts",
        ],
        metadata={
            "category": "reporting",
            "failure_mode_target": "error_handling",
            "note": "Agent should gracefully report the API error, not fabricate data",
        },
    ),
]
