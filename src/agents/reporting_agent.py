"""Reporting agent: synthesizes triage + remediation into actionable reports."""

from strands import Agent

from ..tools.github_alerts import fetch_dependabot_alerts, list_repos_with_alerts
from ..tools.reporting import (
    aggregate_alert_stats,
    build_executive_summary,
    generate_team_assignments,
)

REPORTING_SYSTEM_PROMPT = """\
You are a security reporting agent that produces clear, actionable vulnerability reports
from Dependabot alert data.

Your job:
1. Gather alert data across one or more repositories.
2. Aggregate statistics: counts by severity, ecosystem, age, and fix availability.
3. Produce an executive summary highlighting the most urgent risks.
4. Generate team assignments mapping alerts to responsible teams/owners.

Output a structured report as JSON:
{
  "report_date": "YYYY-MM-DD",
  "scope": "org or repo name",
  "summary": {
    "total_open": N,
    "by_severity": {"critical": N, "high": N, "medium": N, "low": N},
    "by_ecosystem": {"npm": N, "pip": N, ...},
    "fix_available_count": N,
    "oldest_unresolved_days": N,
    "mean_time_to_resolve_days": N
  },
  "top_risks": [
    {
      "alert_number": 123,
      "package": "pkg",
      "severity": "critical",
      "age_days": 30,
      "reason": "why this is the top risk"
    }
  ],
  "team_assignments": [
    {
      "team": "backend",
      "alerts": [123, 456],
      "action_required": "..."
    }
  ],
  "recommendations": ["..."]
}

Rules:
- Always fetch real data with tools. Never fabricate statistics.
- If data is missing or an API call fails, say so explicitly — do not estimate.
- Prioritize clarity over completeness. A shorter accurate report beats a long speculative one.
"""


def create_reporting_agent(**kwargs) -> Agent:
    """Create a reporting agent with alert aggregation and summary tools.

    Args:
        **kwargs: Additional arguments passed to Agent constructor
            (e.g., model, trace_attributes, callback_handler).

    Returns:
        Configured Agent instance for vulnerability reporting.
    """
    return Agent(
        system_prompt=REPORTING_SYSTEM_PROMPT,
        tools=[
            fetch_dependabot_alerts,
            list_repos_with_alerts,
            aggregate_alert_stats,
            build_executive_summary,
            generate_team_assignments,
        ],
        **kwargs,
    )
