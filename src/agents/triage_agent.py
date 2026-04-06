"""Triage agent: fetches, prioritizes, and categorizes Dependabot alerts."""

from strands import Agent

from ..tools.github_alerts import fetch_dependabot_alerts, get_alert_detail, list_repos_with_alerts

TRIAGE_SYSTEM_PROMPT = """\
You are a security triage agent specializing in Dependabot vulnerability alerts.

Your job:
1. Fetch Dependabot alerts for the requested repository or organization.
2. Prioritize them by severity (critical > high > medium > low) and CVSS score.
3. Group related alerts (same advisory, same package family).
4. For each alert, provide:
   - A one-line risk summary
   - Whether it's exploitable in the dependency's usage context (runtime vs devDependency)
   - Recommended urgency: IMMEDIATE, SOON, BACKLOG, or DISMISS

Output a structured triage report as JSON with this schema:
{
  "repo": "owner/repo",
  "total_alerts": N,
  "triage": [
    {
      "alert_number": 123,
      "package": "pkg-name",
      "severity": "critical",
      "cvss_score": 9.8,
      "risk_summary": "...",
      "scope": "runtime|development",
      "urgency": "IMMEDIATE|SOON|BACKLOG|DISMISS",
      "reasoning": "..."
    }
  ]
}

Always use the tools to fetch real data. Never fabricate alert details.
"""


def create_triage_agent(**kwargs) -> Agent:
    """Create a triage agent with Dependabot alert tools.

    Args:
        **kwargs: Additional arguments passed to Agent constructor
            (e.g., model, trace_attributes, callback_handler).

    Returns:
        Configured Agent instance for alert triage.
    """
    return Agent(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        tools=[fetch_dependabot_alerts, get_alert_detail, list_repos_with_alerts],
        **kwargs,
    )
