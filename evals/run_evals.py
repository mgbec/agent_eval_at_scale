"""Run failure-mode evaluations against the Dependabot alert analysis agents.

Usage:
    # Local agents
    python -m evals.run_evals --agent triage
    python -m evals.run_evals --agent all --save

    # Deployed AgentCore agents
    python -m evals.run_evals --agent triage --deployed --arn arn:aws:bedrock-agentcore:...
"""

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path

from strands_evals import Case, Experiment
from strands_evals.evaluators import (
    FaithfulnessEvaluator,
    GoalSuccessRateEvaluator,
    HelpfulnessEvaluator,
    OutputEvaluator,
    TrajectoryEvaluator,
)
from strands_evals.extractors import tools_use_extractor
from strands_evals.mappers import StrandsInMemorySessionMapper
from strands_evals.telemetry import StrandsEvalsTelemetry
from strands_evals.types.evaluation_report import EvaluationReport

from .custom_evaluators import (
    RemediationSafetyEvaluator,
    ReportConsistencyEvaluator,
    SeverityAccuracyEvaluator,
    ToolBeforeClaimEvaluator,
)
from .test_cases import REMEDIATION_CASES, REPORTING_CASES, TRIAGE_CASES

# Telemetry for trace-based evaluators
telemetry = StrandsEvalsTelemetry().setup_in_memory_exporter()


def _make_triage_task():
    """Create the task function for the triage agent."""
    from src.agents.triage_agent import create_triage_agent

    def task_fn(case: Case) -> dict:
        telemetry.memory_exporter.clear()

        agent = create_triage_agent(
            trace_attributes={"session.id": case.session_id},
            callback_handler=None,
        )
        response = agent(case.input)

        trajectory = tools_use_extractor.extract_agent_tools_used_from_messages(
            agent.messages
        )

        spans = telemetry.memory_exporter.get_finished_spans()
        mapper = StrandsInMemorySessionMapper()
        session = mapper.map_to_session(spans, session_id=case.session_id)

        return {
            "output": str(response),
            "trajectory": session,
        }

    return task_fn


def _make_remediation_task():
    """Create the task function for the remediation agent."""
    from src.agents.remediation_agent import create_remediation_agent

    def task_fn(case: Case) -> dict:
        telemetry.memory_exporter.clear()

        agent = create_remediation_agent(
            trace_attributes={"session.id": case.session_id},
            callback_handler=None,
        )
        response = agent(case.input)

        trajectory = tools_use_extractor.extract_agent_tools_used_from_messages(
            agent.messages
        )

        spans = telemetry.memory_exporter.get_finished_spans()
        mapper = StrandsInMemorySessionMapper()
        session = mapper.map_to_session(spans, session_id=case.session_id)

        return {
            "output": str(response),
            "trajectory": session,
        }

    return task_fn


def _make_reporting_task():
    """Create the task function for the reporting agent."""
    from src.agents.reporting_agent import create_reporting_agent

    def task_fn(case: Case) -> dict:
        telemetry.memory_exporter.clear()

        agent = create_reporting_agent(
            trace_attributes={"session.id": case.session_id},
            callback_handler=None,
        )
        response = agent(case.input)

        trajectory = tools_use_extractor.extract_agent_tools_used_from_messages(
            agent.messages
        )

        spans = telemetry.memory_exporter.get_finished_spans()
        mapper = StrandsInMemorySessionMapper()
        session = mapper.map_to_session(spans, session_id=case.session_id)

        return {
            "output": str(response),
            "trajectory": session,
        }

    return task_fn


# --- Deployed AgentCore task factory ---

def _make_deployed_task(agent_arn: str, region: str = "us-east-1"):
    """Create a task function that invokes a deployed AgentCore agent.

    Args:
        agent_arn: The ARN of the deployed AgentCore Runtime.
        region: AWS region where the agent is deployed.
    """
    import boto3

    client = boto3.client("bedrock-agentcore", region_name=region)

    def task_fn(case: Case) -> dict:
        payload = json.dumps({"prompt": case.input}).encode()
        session_id = str(uuid.uuid4())

        response = client.invoke_agent_runtime(
            agentRuntimeArn=agent_arn,
            runtimeSessionId=session_id,
            payload=payload,
            qualifier="DEFAULT",
        )

        content = []
        for chunk in response.get("response", []):
            content.append(chunk.decode("utf-8"))
        result = json.loads("".join(content))

        return {
            "output": result.get("result", str(result)),
        }

    return task_fn


# --- Evaluator configurations per agent type ---

TRIAGE_EVALUATORS = [
    # Did the agent use the right tools?
    TrajectoryEvaluator(
        rubric=(
            "Score 1.0 if the agent called the correct data-fetching tools before producing "
            "a triage report. Score 0.5 if it called some tools but missed key ones. "
            "Score 0.0 if it fabricated data without tool calls."
        )
    ),
    # Is the output faithful to tool results?
    OutputEvaluator(
        rubric=(
            "Evaluate the triage report for: "
            "1. Accuracy — are severity levels and CVSS scores consistent with advisory data? "
            "2. Completeness — are all fetched alerts represented in the triage? "
            "3. Prioritization — are critical/high items ranked above medium/low? "
            "4. Scope awareness — does it distinguish runtime vs dev dependencies? "
            "Score 1.0 if all criteria met. 0.5 if partially met. 0.0 if inadequate."
        )
    ),
    # Custom: did the agent hallucinate severity data?
    SeverityAccuracyEvaluator(),
    # Custom: did the agent call tools before making claims?
    ToolBeforeClaimEvaluator(),
]

REMEDIATION_EVALUATORS = [
    TrajectoryEvaluator(
        rubric=(
            "Score 1.0 if the agent checked fix availability before recommending an upgrade. "
            "Score 0.5 if it partially verified. Score 0.0 if it guessed versions."
        )
    ),
    OutputEvaluator(
        rubric=(
            "Evaluate the remediation plan for: "
            "1. Correctness — does the recommended version actually fix the vulnerability? "
            "2. Safety — does it warn about breaking changes for major bumps? "
            "3. Actionability — are the steps clear and executable? "
            "4. Completeness — does it cover all alerts mentioned in the input? "
            "Score 1.0 if all criteria met. 0.5 if partially met. 0.0 if inadequate."
        )
    ),
    # Custom: is the remediation plan safe?
    RemediationSafetyEvaluator(),
    ToolBeforeClaimEvaluator(),
]

REPORTING_EVALUATORS = [
    TrajectoryEvaluator(
        rubric=(
            "Score 1.0 if the agent fetched alerts, aggregated stats, and built a summary "
            "using the proper tool sequence. Score 0.5 if it skipped aggregation. "
            "Score 0.0 if it fabricated report data without tool calls."
        )
    ),
    OutputEvaluator(
        rubric=(
            "Evaluate the vulnerability report for: "
            "1. Accuracy — do statistics match the raw alert data from tools? "
            "2. Completeness — does it include severity breakdown, age, and fix availability? "
            "3. Actionability — are team assignments and recommendations clear? "
            "4. Error handling — if API calls failed, does it say so instead of guessing? "
            "Score 1.0 if all criteria met. 0.5 if partially met. 0.0 if inadequate."
        )
    ),
    ReportConsistencyEvaluator(),
    ToolBeforeClaimEvaluator(),
    SeverityAccuracyEvaluator(),
]


def run_triage_evals(agent_arn: str | None = None, region: str = "us-east-1") -> list[EvaluationReport]:
    """Run evaluations against the triage agent."""
    experiment = Experiment(cases=TRIAGE_CASES, evaluators=TRIAGE_EVALUATORS)
    task_fn = _make_deployed_task(agent_arn, region) if agent_arn else _make_triage_task()
    reports = experiment.run_evaluations(task_fn)
    return reports


def run_remediation_evals(agent_arn: str | None = None, region: str = "us-east-1") -> list[EvaluationReport]:
    """Run evaluations against the remediation agent."""
    experiment = Experiment(cases=REMEDIATION_CASES, evaluators=REMEDIATION_EVALUATORS)
    task_fn = _make_deployed_task(agent_arn, region) if agent_arn else _make_remediation_task()
    reports = experiment.run_evaluations(task_fn)
    return reports


def run_reporting_evals(agent_arn: str | None = None, region: str = "us-east-1") -> list[EvaluationReport]:
    """Run evaluations against the reporting agent."""
    experiment = Experiment(cases=REPORTING_CASES, evaluators=REPORTING_EVALUATORS)
    task_fn = _make_deployed_task(agent_arn, region) if agent_arn else _make_reporting_task()
    reports = experiment.run_evaluations(task_fn)
    return reports


def print_failure_analysis(reports: list[EvaluationReport], agent_name: str):
    """Print a failure mode breakdown from evaluation reports."""
    print(f"\n{'='*60}")
    print(f"  FAILURE MODE ANALYSIS: {agent_name}")
    print(f"{'='*60}")

    for report in reports:
        total = len(report.test_passes)
        failures = sum(1 for p in report.test_passes if not p)
        print(f"\n[{report.evaluator_name}]")
        print(f"  Score: {report.overall_score:.2f}  |  Failures: {failures}/{total}")

        if failures > 0:
            for i, passed in enumerate(report.test_passes):
                if not passed:
                    case_name = report.cases[i].get("name", f"case-{i}")
                    reason = report.reasons[i][:150] if i < len(report.reasons) else "N/A"
                    metadata = report.cases[i].get("metadata", {})
                    failure_mode = metadata.get("failure_mode_target", "general")
                    print(f"    FAIL [{failure_mode}] {case_name}")
                    print(f"         {reason}")

    # Cross-evaluator failure correlation
    print(f"\n{'─'*60}")
    print("  CROSS-EVALUATOR CORRELATION")
    print(f"{'─'*60}")
    if reports:
        num_cases = len(reports[0].test_passes)
        for i in range(num_cases):
            failing_evaluators = [
                r.evaluator_name
                for r in reports
                if i < len(r.test_passes) and not r.test_passes[i]
            ]
            if failing_evaluators:
                case_name = reports[0].cases[i].get("name", f"case-{i}")
                print(f"  {case_name}: failed on {', '.join(failing_evaluators)}")


def save_reports(reports: list[EvaluationReport], agent_name: str):
    """Save reports to JSON files."""
    output_dir = Path("eval_results")
    output_dir.mkdir(exist_ok=True)

    for report in reports:
        filename = f"{agent_name}_{report.evaluator_name}.json"
        report.to_file(str(output_dir / filename))

    # Also save a combined/flattened report
    combined = EvaluationReport.flatten(reports)
    combined.to_file(str(output_dir / f"{agent_name}_combined.json"))
    print(f"\nReports saved to {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="Run Dependabot alert agent evaluations")
    parser.add_argument(
        "--agent",
        choices=["triage", "remediation", "reporting", "all"],
        default="all",
        help="Which agent to evaluate",
    )
    parser.add_argument("--save", action="store_true", help="Save reports to eval_results/")
    parser.add_argument(
        "--deployed",
        action="store_true",
        help="Evaluate a deployed AgentCore agent instead of local",
    )
    parser.add_argument(
        "--arn",
        type=str,
        default=None,
        help="AgentCore Runtime ARN (required with --deployed)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region for deployed agent (default: us-east-1)",
    )
    args = parser.parse_args()

    if args.deployed and not args.arn:
        parser.error("--arn is required when using --deployed")

    arn = args.arn if args.deployed else None
    region = args.region

    if args.agent in ("triage", "all"):
        reports = run_triage_evals(agent_arn=arn, region=region)
        print_failure_analysis(reports, "Triage Agent")
        if args.save:
            save_reports(reports, "triage")

    if args.agent in ("remediation", "all"):
        reports = run_remediation_evals(agent_arn=arn, region=region)
        print_failure_analysis(reports, "Remediation Agent")
        if args.save:
            save_reports(reports, "remediation")

    if args.agent in ("reporting", "all"):
        reports = run_reporting_evals(agent_arn=arn, region=region)
        print_failure_analysis(reports, "Reporting Agent")
        if args.save:
            save_reports(reports, "reporting")


if __name__ == "__main__":
    main()
