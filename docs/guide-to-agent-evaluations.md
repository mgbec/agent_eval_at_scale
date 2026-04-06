# A Practical Guide to Agent Evaluations

## What Are Agent Evaluations?

When you build an AI agent — a system that can make decisions, call APIs, and take actions on your behalf — you need a way to know if it's doing the right thing. That's where evaluations (evals) come into the picture.

Evals can function like a test mechanism for your agent's judgment. We can use common evals like correct path of tool calls, correctness of final result, and more.  We can also generate custom evals for our specific use case and organization.  Does the end result agree with our company tenets, for example, our company committment to environmental responsibility?

The non deterministic nature of agents and AI require a different approach to evaluation. Ask the same question twice and you might get different answers, different tool calls, or different reasoning paths. Evals account for this by testing across many scenarios and measuring patterns rather than expecting exact matches.

## Why Evaluations Matter

### Agents make mistakes that are hard to spot

Traditional software fails loudly. A null pointer throws an exception. A bad query returns an error. You see it immediately.

Agents fail quietly. An agent might:
- Skip a critical API call and fabricate a plausible-looking answer instead.
- Use the right tool but pass the wrong parameters to it.
- Produce a confident, well-formatted response that is completely wrong.
- Solve 90% of the problem and silently ignore the hardest part.

Without evals, these failures look like successes. The output reads well, the format is correct, and nobody notices the data was made up — until it matters.

### You can't review every response manually

If your agent handles 10 requests a day, you can eyeball the results. If it handles 10,000, you can't. Evals give you automated quality assurance that scales with your usage.

### Agents change when their models change

Even if you don't touch your code, a model update from your provider can change how your agent behaves. Evals act as regression tests — run them after any model change and you'll know immediately if something broke.

## How Evaluations Contribute to Agent Security

This is where evals go from "nice to have" to "essential." Agents that interact with real systems — APIs, databases, infrastructure — can cause real harm when they fail. Here's how evals protect you:

### 1. Preventing hallucinated actions

An agent that fabricates data is annoying. An agent that fabricates data and then acts on it is dangerous.

Example from this project: our triage agent fetches Dependabot vulnerability alerts from GitHub. If it skips the API call and invents alert data, a security team might ignore a real critical vulnerability because the agent said everything was fine. Or they might waste time chasing a vulnerability that doesn't exist.

Our `ToolBeforeClaimEvaluator` catches this by verifying the agent actually called data-fetching tools before producing any alert data.

### 2. Catching dangerous recommendations

Agents that recommend actions need to be evaluated for safety, not just correctness.

Example: our remediation agent suggests how to fix vulnerable dependencies. A "correct" suggestion to upgrade a package could be dangerous if it's a major version bump with breaking changes and the agent doesn't warn you. Worse, an agent might suggest downgrading to a version with known vulnerabilities.

Our `RemediationSafetyEvaluator` specifically checks for these patterns — downgrades, missing breaking change warnings, and invalid remediation actions.

### 3. Ensuring data accuracy in security contexts

Security decisions depend on accurate data. If an agent reports a CVSS score of 3.2 when the real score is 9.8, the vulnerability gets deprioritized and stays unpatched.

Our `SeverityAccuracyEvaluator` validates that severity levels and CVSS scores in the agent's output are valid and within expected ranges. The `ReportConsistencyEvaluator` checks that statistics are internally consistent — severity counts should sum to the total, percentages should match raw numbers.

### 4. Verifying the agent uses the right tools

Agents have access to multiple tools, and picking the wrong one can mean operating on stale or incomplete data.

Example: if you ask for an org-wide vulnerability report and the agent only checks one repository, you get a false sense of security. Trajectory evaluation verifies that the agent called the right tools in the right sequence.

### 5. Testing error handling

What happens when the agent can't access a private repository? A secure agent reports "I couldn't access this repo" and stops. An insecure agent fills in the gaps with guesses and presents them as facts.

Our test cases include scenarios where API calls are expected to fail. These exist specifically to verify that the agent handles errors honestly rather than filling in gaps with fabricated data.

## Types of Agentic Failure

Understanding failure modes helps you design better evals. Here is a practical taxonomy of the some of the main categories:

| Failure Mode | What Happens | Why It's Dangerous | How to Catch It |
|---|---|---|---|
| Wrong tool selection | The agent picks the wrong API or skips a required call. | Decisions are based on incomplete data. | Trajectory evaluation |
| Wrong parameters | The agent calls the right tool but passes incorrect arguments. | It fetches wrong data silently. | Tool parameter evaluation |
| Hallucinated output | The agent invents data instead of fetching it from a source. | Teams act on fabricated results with false confidence. | Tool-before-claim checks and faithfulness evaluation |
| Unsafe recommendations | The agent suggests actions that could cause harm. | These can lead to breaking changes or security regressions. | Domain-specific safety evaluators |
| Goal non-completion | The agent appears to work but doesn't actually solve the problem. | It creates a false sense of resolution. | Goal success rate evaluation |

## How This Project Implements Evaluations

This project uses the [Strands Agents Evals](https://github.com/strands-agents/evals) framework. Here is how the pieces fit together.

### Test cases

Each test case defines an input, which is what you ask the agent. It also includes an expected trajectory that specifies which tools the agent should call, along with metadata describing what failure mode the case is designed to target.

```python
Case(
    name="triage-deep-dive-alert",
    input="Get full details on alert #42 in strands-agents/sdk",
    expected_trajectory=["get_alert_detail"],
    metadata={"failure_mode_target": "hallucination"},
)
```

### Evaluators

Evaluators score the agent's response. Some use LLM-as-a-judge, where another AI model grades the output against a rubric. Others are deterministic checks written in Python.

- The **TrajectoryEvaluator** checks whether the agent called the right tools in the right order.
- The **OutputEvaluator** assesses whether the output meets quality criteria defined in a rubric.
- **Custom evaluators** perform domain-specific checks, such as the `SeverityAccuracyEvaluator` that validates CVSS scores and severity labels.

### Running at scale

```bash
python -m evals.run_evals --agent all --save
```

This command runs every test case against every evaluator for all three agents. It produces a failure analysis with cross-evaluator correlation that shows which cases fail on multiple dimensions, and saves the results as JSON for tracking over time.

### Reading the results

The failure analysis output looks like this:

```
============================================================
  FAILURE MODE ANALYSIS: Triage Agent
============================================================

[TrajectoryEvaluator]
  Score: 0.85  |  Failures: 1/5
    FAIL [hallucination] triage-no-alerts
         Agent produced alert data without calling fetch tools

[SeverityAccuracyEvaluator]
  Score: 1.00  |  Failures: 0/5

──────────────────────────────────────────────────────────
  CROSS-EVALUATOR CORRELATION
──────────────────────────────────────────────────────────
  triage-no-alerts: failed on TrajectoryEvaluator, ToolBeforeClaimEvaluator
```

The cross-evaluator correlation is the most useful part — when a case fails on multiple evaluators simultaneously, that's a systemic issue worth investigating.

## Getting Started with Your Own Evals

If you're building agents and want to add evaluations, start here:

1. **Identify your failure modes.** Ask yourself what the worst thing your agent could do is, and work backwards from there.
2. **Write cases that target each failure mode.** Don't just test the happy path. Include cases where APIs fail, data is missing, or the question is ambiguous.
3. **Layer multiple evaluators.** A single evaluator catches one dimension of failure. Combining trajectory, output, and custom evaluators gives you a multi-dimensional view of agent behavior.
4. **Run evals on every model change.** Treat them like regression tests. If scores drop after a model update, investigate before deploying.
5. **Track results over time.** Save eval results as JSON and compare across runs. Trends over time matter more than any individual score.

## Further Reading

- [Strands Agents Evals documentation](https://github.com/strands-agents/evals)
- [This project's README](../README.md) for setup and usage instructions
