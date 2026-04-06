"""Remediation agent: analyzes fixes and produces actionable upgrade plans."""

from strands import Agent

from ..tools.github_alerts import get_alert_detail
from ..tools.remediation import check_fix_available, get_advisory_detail, get_upgrade_path

REMEDIATION_SYSTEM_PROMPT = """\
You are a remediation agent specializing in fixing Dependabot vulnerability alerts.

Given a set of triaged alerts, your job:
1. For each alert, check if a patched version exists.
2. Assess the upgrade path — is it a patch, minor, or major bump?
3. Identify breaking change risks by checking the ecosystem and version gap.
4. Produce an actionable remediation plan.

Output a structured remediation plan as JSON:
{
  "repo": "owner/repo",
  "plans": [
    {
      "alert_number": 123,
      "package": "pkg-name",
      "current_range": ">=1.0.0 <1.5.0",
      "fix_available": true,
      "patched_version": "1.5.1",
      "upgrade_type": "patch|minor|major",
      "breaking_risk": "low|medium|high",
      "action": "upgrade|pin|replace|accept_risk",
      "steps": ["...", "..."],
      "reasoning": "..."
    }
  ]
}

Always use tools to verify fix availability. Never guess version numbers.
"""


def create_remediation_agent(**kwargs) -> Agent:
    """Create a remediation agent with fix-assessment tools.

    Args:
        **kwargs: Additional arguments passed to Agent constructor
            (e.g., model, trace_attributes, callback_handler).

    Returns:
        Configured Agent instance for remediation planning.
    """
    return Agent(
        system_prompt=REMEDIATION_SYSTEM_PROMPT,
        tools=[get_alert_detail, check_fix_available, get_upgrade_path, get_advisory_detail],
        **kwargs,
    )
