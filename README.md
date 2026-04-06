# Dependabot Alert Analyzer

AI agents that triage and remediate Dependabot vulnerability alerts, with a comprehensive evaluation suite for detecting agentic failure modes at scale.

## Architecture

```
src/
  agents/
    triage_agent.py        # Fetches, prioritizes, categorizes alerts
    remediation_agent.py   # Assesses fixes, produces upgrade plans
    reporting_agent.py     # Aggregates stats, builds executive summaries, assigns teams
  tools/
    github_alerts.py       # GitHub Dependabot API wrappers
    remediation.py         # Fix assessment and advisory lookup tools
    reporting.py           # Alert aggregation, executive summaries, team assignments
evals/
    test_cases.py          # Curated cases targeting specific failure modes
    custom_evaluators.py   # Domain-specific evaluators (severity, safety, grounding, consistency)
    run_evals.py           # Evaluation runner with failure analysis reporting
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Authentication

The tools authenticate with GitHub using this priority:

1. **GitHub CLI (recommended)** — if `gh` is installed and you're logged in, it just works:
   ```bash
   gh auth login
   ```
2. **Environment variable** — set `GITHUB_TOKEN` manually:
   ```bash
   export GITHUB_TOKEN=ghp_your_token_here   # Linux/macOS
   set GITHUB_TOKEN=ghp_your_token_here      # Windows cmd
   $env:GITHUB_TOKEN="ghp_your_token_here"   # Windows PowerShell
   ```

The token is resolved once and cached for the process lifetime. If neither method is available, API calls will run unauthenticated (lower rate limits, no access to private repos).

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
