"""Tools for fetching Dependabot alerts from GitHub API."""

import json
import os
from typing import Any

import requests

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def _gh_get(url: str, params: dict | None = None) -> dict | list:
    resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def list_repos_with_alerts(org: str, severity: str = "") -> str:
    """List repositories in an org that have open Dependabot alerts.

    Args:
        org: GitHub organization name.
        severity: Filter by severity (critical, high, medium, low). Empty = all.

    Returns:
        JSON string with repo names and alert counts.
    """
    params: dict[str, Any] = {"state": "open", "per_page": 100}
    if severity:
        params["severity"] = severity

    try:
        alerts = _gh_get(f"{GITHUB_API}/orgs/{org}/dependabot/alerts", params)
        repo_counts: dict[str, int] = {}
        for alert in alerts:
            repo_name = alert.get("repository", {}).get("full_name", "unknown")
            repo_counts[repo_name] = repo_counts.get(repo_name, 0) + 1
        return json.dumps(
            {"org": org, "repos_with_alerts": repo_counts, "total_alerts": sum(repo_counts.values())},
            indent=2,
        )
    except requests.HTTPError as e:
        return json.dumps({"error": str(e), "status_code": e.response.status_code})


def fetch_dependabot_alerts(owner: str, repo: str, state: str = "open", severity: str = "") -> str:
    """Fetch Dependabot alerts for a specific repository.

    Args:
        owner: Repository owner (user or org).
        repo: Repository name.
        state: Alert state filter (open, fixed, dismissed). Default: open.
        severity: Filter by severity (critical, high, medium, low). Empty = all.

    Returns:
        JSON string with alert summaries.
    """
    params: dict[str, Any] = {"state": state, "per_page": 100}
    if severity:
        params["severity"] = severity

    try:
        alerts = _gh_get(f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts", params)
        summaries = []
        for a in alerts:
            vuln = a.get("security_vulnerability", {})
            advisory = a.get("security_advisory", {})
            summaries.append({
                "number": a.get("number"),
                "state": a.get("state"),
                "package": vuln.get("package", {}).get("name"),
                "ecosystem": vuln.get("package", {}).get("ecosystem"),
                "severity": vuln.get("severity"),
                "vulnerable_range": vuln.get("vulnerable_version_range"),
                "patched_version": vuln.get("first_patched_version", {}).get("identifier"),
                "advisory_summary": advisory.get("summary"),
                "cvss_score": advisory.get("cvss", {}).get("score"),
                "cwe": [c.get("cwe_id") for c in advisory.get("cwes", [])],
                "created_at": a.get("created_at"),
            })
        return json.dumps({"owner": owner, "repo": repo, "alerts": summaries}, indent=2)
    except requests.HTTPError as e:
        return json.dumps({"error": str(e), "status_code": e.response.status_code})


def get_alert_detail(owner: str, repo: str, alert_number: int) -> str:
    """Get full details for a specific Dependabot alert.

    Args:
        owner: Repository owner.
        repo: Repository name.
        alert_number: The alert number.

    Returns:
        JSON string with complete alert details including advisory, references, and fix info.
    """
    try:
        alert = _gh_get(f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts/{alert_number}")
        vuln = alert.get("security_vulnerability", {})
        advisory = alert.get("security_advisory", {})
        return json.dumps({
            "number": alert.get("number"),
            "state": alert.get("state"),
            "dependency": {
                "package": vuln.get("package", {}).get("name"),
                "ecosystem": vuln.get("package", {}).get("ecosystem"),
                "manifest_path": alert.get("dependency", {}).get("manifest_path"),
                "scope": alert.get("dependency", {}).get("scope"),
            },
            "vulnerability": {
                "severity": vuln.get("severity"),
                "vulnerable_range": vuln.get("vulnerable_version_range"),
                "patched_version": vuln.get("first_patched_version", {}).get("identifier"),
            },
            "advisory": {
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "summary": advisory.get("summary"),
                "description": advisory.get("description"),
                "cvss_score": advisory.get("cvss", {}).get("score"),
                "cvss_vector": advisory.get("cvss", {}).get("vector_string"),
                "cwes": [{"id": c.get("cwe_id"), "name": c.get("name")} for c in advisory.get("cwes", [])],
                "references": [r.get("url") for r in advisory.get("references", [])],
            },
            "auto_dismissed_at": alert.get("auto_dismissed_at"),
            "created_at": alert.get("created_at"),
            "updated_at": alert.get("updated_at"),
            "dismissed_reason": alert.get("dismissed_reason"),
            "dismissed_comment": alert.get("dismissed_comment"),
        }, indent=2)
    except requests.HTTPError as e:
        return json.dumps({"error": str(e), "status_code": e.response.status_code})
