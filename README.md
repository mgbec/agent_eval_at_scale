# Dependabot Alert Analyzer

AI agents that triage and remediate Dependabot vulnerability alerts, with a comprehensive evaluation suite for detecting agentic failure modes at scale.

## Architecture

```
src/
  agents/
    triage_agent.py        # Fetches, prioritizes, categorizes alerts
    remediation_agent.py   # Assesses fixes, produces upgrade plans
  tools/
    github_alerts.py       # GitHub Dependabot API wrappers
    remediation.py         # Fix assessment and advisory lookup tools
evals/
    test_cases.py          # Curated cases targeting specific failure modes
    custom_evaluators.py   # Domain-specific evaluators (severity, safety, grounding)
    run_evals.py           # Evaluation runner with failure analysis reporting
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
export GITHUB_TOKEN=ghp_your_token_here
```

## Usage

### Run the agents directly
```python
from src.agents import create_triage_agent, create_remediation_agent

agent = create_triage_agent()
result = agent("Triage Dependabot alerts for owner=myorg repo=myapp")
```

### Run failure mode evaluations
```bash
# Evaluate triage agent
python -m evals.run_evals --agent triage --save

# Evaluate remediation agent
python -m evals.run_evals --agent remediation --save

# Evaluate both
python -m evals.run_evals --agent all --save
```

## Failure Modes Covered

| Failure Mode | Evaluator | What It Catches |
|---|---|---|
| Hallucinated data | ToolBeforeClaimEvaluator | Agent fabricates alerts without calling tools |
| Wrong severity | SeverityAccuracyEvaluator | Invalid CVSS scores or severity labels |
| Unsafe remediation | RemediationSafetyEvaluator | Downgrades, missing breaking change warnings |
| Wrong tool selection | TrajectoryEvaluator | Agent picks wrong tools or skips required ones |
| Unfaithful output | OutputEvaluator (rubric) | Output contradicts tool results |
| Goal non-completion | GoalSuccessRateEvaluator | Agent doesn't actually solve the problem |
