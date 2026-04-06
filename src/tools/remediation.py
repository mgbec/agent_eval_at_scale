"""Tools for assessing remediation options for Dependabot alerts."""

import json
import os

import requests

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def check_fix_available(owner: str, repo: str, alert_number: int) -> str:
    """Check if a fix (patched version) is available for a Dependabot alert.

    Args:
        owner: Repository owner.
        repo: Repository name.
        alert_number: The alert number.

    Returns:
        JSON with fix availability, patched version, and whether auto-fix PR exists.
    """
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts/{alert_number}"
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        alert = resp.json()

        vuln = alert.get("security_vulnerability", {})
        patched = vuln.get("first_patched_version", {}).get("identifier")
        return json.dumps({
            "alert_number": alert_number,
            "fix_available": patched is not None,
            "patched_version": patched,
            "current_vulnerable_range": vuln.get("vulnerable_version_range"),
            "auto_dismissed": alert.get("auto_dismissed_at") is not None,
        }, indent=2)
    except requests.HTTPError as e:
        return json.dumps({"error": str(e), "status_code": e.response.status_code})


def get_upgrade_path(package_name: str, ecosystem: str, current_range: str) -> str:
    """Determine the upgrade path for a vulnerable package.

    Args:
        package_name: Name of the package.
        ecosystem: Package ecosystem (npm, pip, maven, etc.).
        current_range: Current vulnerable version range string.

    Returns:
        JSON with upgrade recommendation and breaking change risk assessment.
    """
    # In production you'd query the registry API (npm, PyPI, Maven Central, etc.)
    # This is a structured stub that the agent uses to reason about upgrades
    return json.dumps({
        "package": package_name,
        "ecosystem": ecosystem,
        "current_vulnerable_range": current_range,
        "recommendation": (
            f"Upgrade {package_name} to the latest patched version. "
            f"Check the package changelog for breaking changes before upgrading."
        ),
        "risk_factors": [
            "Major version bump may introduce breaking API changes",
            "Transitive dependencies may also need updates",
            "Test suite should be run after upgrade",
        ],
    }, indent=2)


def get_advisory_detail(ghsa_id: str) -> str:
    """Fetch detailed advisory information from GitHub Advisory Database.

    Args:
        ghsa_id: GitHub Security Advisory ID (e.g., GHSA-xxxx-xxxx-xxxx).

    Returns:
        JSON with full advisory details including affected versions, severity, and references.
    """
    try:
        url = f"https://api.github.com/advisories/{ghsa_id}"
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        adv = resp.json()
        return json.dumps({
            "ghsa_id": adv.get("ghsa_id"),
            "cve_id": adv.get("cve_id"),
            "summary": adv.get("summary"),
            "description": adv.get("description"),
            "severity": adv.get("severity"),
            "cvss_score": adv.get("cvss", {}).get("score"),
            "published_at": adv.get("published_at"),
            "updated_at": adv.get("updated_at"),
            "withdrawn_at": adv.get("withdrawn_at"),
            "vulnerabilities": [
                {
                    "package": v.get("package", {}).get("name"),
                    "ecosystem": v.get("package", {}).get("ecosystem"),
                    "vulnerable_range": v.get("vulnerable_version_range"),
                    "patched_version": v.get("first_patched_version", {}).get("identifier"),
                }
                for v in adv.get("vulnerabilities", [])
            ],
            "references": [r.get("url") for r in adv.get("references", [])],
        }, indent=2)
    except requests.HTTPError as e:
        return json.dumps({"error": str(e), "status_code": e.response.status_code})
