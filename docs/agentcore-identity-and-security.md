# AgentCore Identity and Security

How Amazon Bedrock AgentCore handles identity, authentication, and secure interactions between agents, users, and external services.

## The Problem AgentCore Identity Solves

Traditional application security wasn't designed for AI agents. Agents introduce new challenges:

- An agent might need to access GitHub on behalf of one user, then Slack on behalf of another
- Multiple agents need to communicate with each other without sharing credentials
- Every action an agent takes needs to be auditable — who asked for it, which agent did it, what resources were touched
- In multi-tenant environments, one customer's agent must never access another customer's data

Building all of this from scratch means months of custom OAuth flows, token vaults, and audit infrastructure. AgentCore Identity provides it as a managed service.

## Core Components

### Agent Identity Directory

Every agent deployed to AgentCore gets a unique identity — an ARN, metadata, and associated configuration. Agents are first-class security principals, not just applications borrowing a user's credentials or sharing a service account.

This means you can answer "which agent did what" in your audit logs, not just "which IAM role was used."

### Agent Authorizer (Inbound Authentication)

Controls who can invoke your agent. Every request is validated before it reaches your agent code.

Supported patterns:
- AWS IAM (SigV4) for service-to-service calls and other AWS resources
- JWT validation via OAuth 2.0 / OpenID Connect for user-facing applications
- Integration with existing identity providers: Amazon Cognito, Okta, Microsoft Entra ID, and any OAuth 2.0 / OIDC-compatible provider

Example: configuring a JWT authorizer backed by Cognito:

```python
agentcore_runtime.configure(
    entrypoint="triage_runtime.py",
    authorizer_configuration={
        "customJWTAuthorizer": {
            "discoveryUrl": f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration",
            "allowedClients": [client_id]
        }
    }
)
```

### Resource Credential Provider (Outbound Authentication)

Controls what your agent can access. Manages OAuth flows and credential retrieval for external services.

Three patterns:
- Three-legged OAuth (user delegation): agent acts on behalf of a specific user with their consent
- Two-legged OAuth (machine-to-machine): agent authenticates as itself
- API keys: for simpler integrations

AgentCore provides pre-configured providers for popular services including GitHub, Slack, and Salesforce.

Example: registering GitHub as an OAuth provider:

```python
agentcore_client.create_oauth2_credential_provider(
    name="github-provider",
    credentialProviderVendor="GithubOauth2",
    oauth2ProviderConfigInput={
        "githubOauth2ProviderConfig": {
            "clientId": "<your-github-client-id>",
            "clientSecret": "<your-github-client-secret>"
        }
    }
)
```

### Token Vault

Securely stores all OAuth tokens and API keys:
- Encrypted with customer-managed AWS KMS keys
- Tokens are bound to specific agent-user pairs — no sharing across users or agents
- Automatic token refresh to minimize credential exposure
- Access controlled so only the authorized agent can retrieve tokens for its assigned users

## How This Applies to the Dependabot Analyzer

### Current approach (Secrets Manager)

Right now, our agents use a shared GitHub Personal Access Token stored in AWS Secrets Manager. This works, but it means:
- All three agents share the same token with the same permissions
- Every user's request uses the same GitHub identity
- There's no per-user scoping — the token can access any repo it was granted access to

### With AgentCore Identity

You could register GitHub as an OAuth credential provider. Each agent gets its own identity, and when a user invokes the triage agent, the three-legged OAuth flow gets a token scoped to that user's GitHub permissions.

```python
from bedrock_agentcore.identity.auth import requires_access_token

@tool
@requires_access_token(
    provider_name="github-provider",
    scopes=["repo", "read:user"],
    auth_flow="USER_FEDERATION",
)
async def fetch_dependabot_alerts(*, access_token: str, owner: str, repo: str) -> str:
    """Fetch alerts using the authenticated user's GitHub token."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    # ... fetch alerts with per-user scoped token
```

Benefits:
- Each user's agent invocation accesses only repos they have permission to see
- No shared service token — if one user's token is compromised, others are unaffected
- The token vault handles refresh and storage automatically
- Full audit trail: which user, which agent, which repos, when

## Agent-to-Agent Communication

When the reporting agent needs to call the triage agent to gather data before building a report, the security model works like this:

1. The reporting agent authenticates to the triage agent via SigV4 (both are AWS resources with their own identities)
2. Each agent maintains its own outbound credentials — the triage agent's GitHub read scope stays separate from a remediation agent's write scope
3. The token vault enforces agent-user pair binding, so the reporting agent can't use the triage agent's tokens
4. Every hop is logged to CloudWatch with both agent identities and the originating user

```
User (JWT) → Reporting Agent (ARN-1) → Triage Agent (ARN-2) → GitHub API
     ↑              ↑                        ↑                    ↑
  Validated    Own identity            Own identity          User-scoped
  by authorizer  in audit log          in audit log          OAuth token
```

## Multi-Tenant Security

For organizations running the analyzer across multiple teams or customers:

- Configure separate credential providers per tenant
- Use tenant-specific JWT claims for validation at the authorizer level
- The token vault's agent-user pair binding prevents cross-tenant data leakage automatically
- Additional authorization checks can be implemented in agent logic for fine-grained control

## Security Best Practices

### Least privilege
Grant each agent only the minimum GitHub scopes it needs. The triage agent needs `repo:read` and `security_events:read`. The remediation agent might need `repo:write` for creating PRs. Don't give both agents the same broad scope.

### Token lifecycle
- Enable automatic token refresh (AgentCore handles this)
- Use `force_authentication=True` for sensitive operations like dismissing alerts or creating remediation PRs
- Set token expiration policies appropriate for your use case

### Audit and monitoring
- Enable CloudWatch logging for all agent operations
- Set up alerts for unusual patterns: unexpected repos accessed, high-frequency invocations, failed auth attempts
- Review audit logs regularly for compliance

### Credential isolation
- Never pass tokens between agents manually
- Let AgentCore Identity manage the full credential lifecycle
- Use the `@requires_access_token` decorator rather than fetching tokens yourself

## Further Reading

- [AgentCore Identity announcement](https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-identity-securing-agentic-ai-at-scale/)
- [AgentCore documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [Strands Agents deployment guide](https://strandsagents.com/docs/user-guide/deploy/deploy_to_bedrock_agentcore/python/)

Sources referenced above were rephrased for compliance with licensing restrictions.
