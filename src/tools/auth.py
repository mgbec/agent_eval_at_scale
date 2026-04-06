"""GitHub authentication helper.

Resolves a token using this priority:
1. AWS Secrets Manager (for AgentCore / cloud deployments)
2. `gh auth token` (GitHub CLI) — for local development
3. GITHUB_TOKEN environment variable

Usage:
    from .auth import get_github_headers

    resp = requests.get(url, headers=get_github_headers(), timeout=30)
"""

import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

_cached_token: str | None = None

# Configure via env vars for cloud deployments
GITHUB_SECRET_NAME = os.environ.get(
    "GITHUB_SECRET_NAME", "dependabot-analyzer/github-token"
)
GITHUB_SECRET_REGION = os.environ.get("AWS_REGION", "us-east-1")


def _get_token_from_secrets_manager() -> str | None:
    """Attempt to get a token from AWS Secrets Manager."""
    try:
        import boto3

        client = boto3.client(
            "secretsmanager", region_name=GITHUB_SECRET_REGION
        )
        resp = client.get_secret_value(SecretId=GITHUB_SECRET_NAME)
        secret = json.loads(resp["SecretString"])
        token = secret.get("GITHUB_TOKEN", "")
        if token:
            logger.debug("Authenticated via AWS Secrets Manager")
            return token
    except ImportError:
        logger.debug("boto3 not available, skipping Secrets Manager")
    except Exception as e:
        logger.debug("Secrets Manager lookup failed: %s", e)
    return None


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
    """Get a GitHub token using the priority chain.

    Priority:
        1. AWS Secrets Manager (cloud)
        2. GitHub CLI (local dev)
        3. GITHUB_TOKEN env var (CI / manual)

    Returns:
        A GitHub token string, or empty string if none found.
    """
    global _cached_token
    if _cached_token is not None:
        return _cached_token

    # Priority 1: AWS Secrets Manager
    token = _get_token_from_secrets_manager()
    if token:
        _cached_token = token
        return token

    # Priority 2: GitHub CLI
    token = _get_token_from_gh_cli()
    if token:
        _cached_token = token
        return token

    # Priority 3: Environment variable
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        logger.debug("Authenticated via GITHUB_TOKEN env var")
        _cached_token = token
        return token

    logger.warning(
        "No GitHub token found. "
        "Run 'gh auth login', set GITHUB_TOKEN, "
        "or configure AWS Secrets Manager."
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
