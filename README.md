# Dependabot Alert Analyzer

AI agents that triage and remediate Dependabot vulnerability alerts, deployable to AWS Bedrock AgentCore, with a comprehensive evaluation suite for detecting agentic failure modes at scale.

## Architecture

```
src/
  agents/
    triage_agent.py        # Fetches, prioritizes, categorizes alerts
    remediation_agent.py   # Assesses fixes, produces upgrade plans
    reporting_agent.py     # Aggregates stats, builds executive summaries, assigns teams
  runtime/
    triage_runtime.py      # AgentCore entrypoint for triage agent
    remediation_runtime.py # AgentCore entrypoint for remediation agent
    reporting_runtime.py   # AgentCore entrypoint for reporting agent
  tools/
    auth.py                # GitHub auth (Secrets Manager → gh CLI → env var)
    github_alerts.py       # GitHub Dependabot API wrappers
    remediation.py         # Fix assessment and advisory lookup tools
    reporting.py           # Alert aggregation, executive summaries, team assignments
evals/
    test_cases.py          # Curated cases targeting specific failure modes
    custom_evaluators.py   # Domain-specific evaluators (severity, safety, grounding, consistency)
    run_evals.py           # Evaluation runner with failure analysis reporting
docs/
    guide-to-agent-evaluations.md      # Beginner-friendly intro to agent evals and security
    agentcore-identity-and-security.md # How AgentCore handles agent identity and auth
    references.md                      # Links to all referenced documentation
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Authentication

The tools authenticate with GitHub using this priority:

1. **AWS Secrets Manager (cloud)** — for AgentCore deployments:
   ```bash
   aws secretsmanager create-secret \
     --name dependabot-analyzer/github-token \
     --secret-string '{"GITHUB_TOKEN":"ghp_your_token"}'
   ```
   Configure the secret name via `GITHUB_SECRET_NAME` env var (defaults to `dependabot-analyzer/github-token`).

2. **GitHub CLI (local dev)** — if `gh` is installed and you're logged in:
   ```bash
   gh auth login
   ```

3. **Environment variable** — set `GITHUB_TOKEN` manually:
   ```bash
   export GITHUB_TOKEN=ghp_your_token_here   # Linux/macOS
   set GITHUB_TOKEN=ghp_your_token_here      # Windows cmd
   $env:GITHUB_TOKEN="ghp_your_token_here"   # Windows PowerShell
   ```

The token is resolved once and cached for the process lifetime.

## Usage

### Run the agents directly
```python
from src.agents import create_triage_agent, create_remediation_agent, create_reporting_agent

agent = create_triage_agent()
result = agent("Triage Dependabot alerts for owner=myorg repo=myapp")

reporter = create_reporting_agent()
report = reporter("Generate a vulnerability report for owner=myorg repo=myapp")
```

### Run failure mode evaluations
```bash
# Evaluate triage agent
python -m evals.run_evals --agent triage --save

# Evaluate remediation agent
python -m evals.run_evals --agent remediation --save

# Evaluate reporting agent
python -m evals.run_evals --agent reporting --save

# Evaluate all three
python -m evals.run_evals --agent all --save
```

### Evaluate deployed AgentCore agents
```bash
# Evaluate a deployed agent by ARN
python -m evals.run_evals --agent triage --deployed \
  --arn arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/triage-agent-abc123 \
  --region us-east-1 --save
```

## Deploy to AWS AgentCore

Install the AgentCore dependencies:
```bash
pip install -e ".[agentcore]"
```

### 1. Store the GitHub token in Secrets Manager
```bash
aws secretsmanager create-secret \
  --name dependabot-analyzer/github-token \
  --secret-string '{"GITHUB_TOKEN":"ghp_your_token"}'
```

### 2. Test locally
```bash
# Start the triage agent locally
python src/runtime/triage_runtime.py

# In another terminal
curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Triage Dependabot alerts for owner=myorg repo=myapp"}'
```

### 3. Configure and deploy
```bash
# Configure (repeat for each agent with its entrypoint)
agentcore configure -e src/runtime/triage_runtime.py

# Deploy to AgentCore Runtime
agentcore deploy

# Test the deployed agent
agentcore invoke '{"prompt": "Triage Dependabot alerts for owner=myorg repo=myapp"}'
```

### 4. Enable observability
Add `aws-opentelemetry-distro` (already in `requirements.txt`) and run with auto-instrumentation:
```bash
opentelemetry-instrument python src/runtime/triage_runtime.py
```
Traces flow to CloudWatch automatically when deployed to AgentCore.

## Failure Modes Covered

| Failure Mode | Evaluator | What It Catches |
|---|---|---|
| Hallucinated data | ToolBeforeClaimEvaluator | Agent fabricates alerts without calling tools |
| Wrong severity | SeverityAccuracyEvaluator | Invalid CVSS scores or severity labels |
| Unsafe remediation | RemediationSafetyEvaluator | Downgrades, missing breaking change warnings |
| Inconsistent stats | ReportConsistencyEvaluator | Severity counts don't sum to total, mixed error/data signals |
| Wrong tool selection | TrajectoryEvaluator | Agent picks wrong tools or skips required ones |
| Unfaithful output | OutputEvaluator (rubric) | Output contradicts tool results |
| Goal non-completion | GoalSuccessRateEvaluator | Agent doesn't actually solve the problem |

## Documentation

- [Guide to Agent Evaluations](docs/guide-to-agent-evaluations.md) — why evaluations matter, how they contribute to agent security, and how to get started
- [AgentCore Identity and Security](docs/agentcore-identity-and-security.md) — how AgentCore handles agent identity, inbound/outbound auth, token vaults, and agent-to-agent communication
- [References](docs/references.md) — links to all external documentation and resources
