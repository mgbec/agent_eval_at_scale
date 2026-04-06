"""Tools for aggregating and summarizing Dependabot alert data into reports."""

import json
from datetime import datetime, timezone


def aggregate_alert_stats(alerts_json: str) -> str:
    """Aggregate statistics from a list of Dependabot alerts.

    Args:
        alerts_json: JSON string from fetch_dependabot_alerts output
            (must contain an "alerts" array).

    Returns:
        JSON string with aggregated counts by severity, ecosystem,
        fix availability, and age distribution.
    """
    try:
        data = json.loads(alerts_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    alerts = data.get("alerts", [])
    if not alerts:
        return json.dumps({"total": 0, "message": "No alerts to aggregate"})

    by_severity = {}
    by_ecosystem = {}
    fix_available = 0
    ages_days = []
    now = datetime.now(timezone.utc)

    for a in alerts:
        sev = a.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        eco = a.get("ecosystem", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1

        if a.get("patched_version"):
            fix_available += 1

        created = a.get("created_at")
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                ages_days.append((now - created_dt).days)
            except (ValueError, TypeError):
                pass

    stats = {
        "total": len(alerts),
        "by_severity": by_severity,
        "by_ecosystem": by_ecosystem,
        "fix_available_count": fix_available,
        "fix_available_pct": round(fix_available / len(alerts) * 100, 1) if alerts else 0,
        "age_distribution": {
            "oldest_days": max(ages_days) if ages_days else None,
            "newest_days": min(ages_days) if ages_days else None,
            "mean_days": round(sum(ages_days) / len(ages_days), 1) if ages_days else None,
            "over_30_days": sum(1 for d in ages_days if d > 30),
            "over_90_days": sum(1 for d in ages_days if d > 90),
        },
    }
    return json.dumps(stats, indent=2)


def build_executive_summary(
    stats_json: str, repo_or_org: str, report_date: str = ""
) -> str:
    """Build an executive summary from aggregated alert statistics.

    Args:
        stats_json: JSON string from aggregate_alert_stats output.
        repo_or_org: The repository or organization name for the report header.
        report_date: Optional date string (YYYY-MM-DD). Defaults to today.

    Returns:
        JSON string with a structured executive summary including
        risk highlights and recommended actions.
    """
    try:
        stats = json.loads(stats_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid stats JSON"})

    if not report_date:
        report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})
    age = stats.get("age_distribution", {})

    risk_level = "LOW"
    if by_sev.get("critical", 0) > 0:
        risk_level = "CRITICAL"
    elif by_sev.get("high", 0) > 0:
        risk_level = "HIGH"
    elif by_sev.get("medium", 0) > 0:
        risk_level = "MEDIUM"

    highlights = []
    if by_sev.get("critical", 0) > 0:
        highlights.append(
            f"{by_sev['critical']} critical vulnerabilities require immediate attention"
        )
    if age.get("over_90_days", 0) > 0:
        highlights.append(
            f"{age['over_90_days']} alerts are older than 90 days and may indicate stale dependencies"
        )
    fix_pct = stats.get("fix_available_pct", 0)
    if fix_pct > 0:
        highlights.append(
            f"{fix_pct}% of alerts have patches available — quick wins for remediation"
        )

    return json.dumps({
        "report_date": report_date,
        "scope": repo_or_org,
        "overall_risk_level": risk_level,
        "total_open_alerts": total,
        "highlights": highlights,
        "severity_breakdown": by_sev,
        "age_summary": age,
    }, indent=2)


def generate_team_assignments(
    alerts_json: str, team_mapping_json: str = ""
) -> str:
    """Map alerts to responsible teams based on ecosystem or manifest path.

    Args:
        alerts_json: JSON string from fetch_dependabot_alerts output.
        team_mapping_json: Optional JSON mapping ecosystems/paths to team names.
            Example: '{"npm": "frontend", "pip": "backend", "maven": "platform"}'
            If empty, assigns by ecosystem with sensible defaults.

    Returns:
        JSON string with alerts grouped by team with action summaries.
    """
    try:
        data = json.loads(alerts_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid alerts JSON"})

    default_mapping = {
        "npm": "frontend",
        "pip": "backend",
        "maven": "platform",
        "nuget": "dotnet",
        "rubygems": "backend",
        "go": "platform",
        "rust": "platform",
    }

    if team_mapping_json:
        try:
            team_map = json.loads(team_mapping_json)
        except json.JSONDecodeError:
            team_map = default_mapping
    else:
        team_map = default_mapping

    alerts = data.get("alerts", [])
    teams: dict[str, list] = {}

    for a in alerts:
        eco = (a.get("ecosystem") or "unknown").lower()
        team = team_map.get(eco, "unassigned")
        teams.setdefault(team, []).append({
            "alert_number": a.get("number"),
            "package": a.get("package"),
            "severity": a.get("severity"),
            "has_fix": a.get("patched_version") is not None,
        })

    assignments = []
    for team_name, team_alerts in teams.items():
        critical_count = sum(1 for a in team_alerts if a["severity"] == "critical")
        fixable = sum(1 for a in team_alerts if a["has_fix"])
        assignments.append({
            "team": team_name,
            "alert_count": len(team_alerts),
            "critical_count": critical_count,
            "fixable_count": fixable,
            "alerts": team_alerts,
            "action_required": (
                f"Address {critical_count} critical alerts immediately. "
                f"{fixable} alerts have patches available."
                if critical_count > 0
                else f"Review {len(team_alerts)} alerts. {fixable} have patches available."
            ),
        })

    assignments.sort(key=lambda x: x["critical_count"], reverse=True)
    return json.dumps({"team_assignments": assignments}, indent=2)
