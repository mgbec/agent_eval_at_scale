"""GitHub authentication helper.

Resolves a token using this priority:
1. `gh auth token` (GitHub CLI) — if gh is installed and authenticated
2. GITHUB_TOKEN environment variable

Usage:
    from .auth import get_github_headers

    resp = requests.get(url, headers=get_github_headers(), timeout=30)
"""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

_cached_token: str | None = None


def _get_token_from_gh_cli() -> str | None:
    """Attempt to get a token from the GitHub CLI."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.debug("Authenticated via GitHub CLI")
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def get_github_token() -> str:
    """Get a GitHub token, trying gh CLI first then env var.

    Returns:
        A GitHub token string, or empty string if none found.
    """
    global _cached_token
    if _cached_token is not None:
        return _cached_token

    # Priority 1: GitHub CLI
    token = _get_token_from_gh_cli()
    if token:
        _cached_token = token
        return token

    # Priority 2: Environment variable
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        logger.debug("Authenticated via GITHUB_TOKEN env var")
        _cached_token = token
        return token

    logger.warning(
        "No GitHub token found. Run 'gh auth login' or set GITHUB_TOKEN."
    )
    _cached_token = ""
    return ""


def get_github_headers() -> dict[str, str]:
    """Build GitHub API request headers with authentication.

    Returns:
        Dict of HTTP headers for GitHub API requests.
    """
    token = get_github_token()
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers
