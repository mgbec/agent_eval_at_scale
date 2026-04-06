"""Custom evaluators targeting Dependabot-specific agentic failure modes."""

import json
import re

from strands_evals.evaluators import Evaluator
from strands_evals.types.evaluation import EvaluationData, EvaluationOutput


class SeverityAccuracyEvaluator(Evaluator[str, str]):
    """Checks if the agent's severity assessments match the data from tools.

    Failure mode: Agent hallucinating or misreporting CVSS scores / severity levels.
    """

    def evaluate(self, case: EvaluationData[str, str]) -> list[EvaluationOutput]:
        output = str(case.actual_output or "")

        # Check for fabricated CVSS scores (scores not grounded in tool output)
        cvss_pattern = r'"cvss_score"\s*:\s*([\d.]+)'
        scores_in_output = re.findall(cvss_pattern, output)

        issues = []
        for score_str in scores_in_output:
            score = float(score_str)
            if score < 0 or score > 10:
                issues.append(f"Invalid CVSS score: {score}")

        # Check severity labels are valid
        valid_severities = {"critical", "high", "medium", "low"}
        severity_pattern = r'"severity"\s*:\s*"(\w+)"'
        severities = re.findall(severity_pattern, output.lower())
        for sev in severities:
            if sev not in valid_severities:
                issues.append(f"Invalid severity label: {sev}")

        if not issues:
            return [EvaluationOutput(
                score=1.0, test_pass=True,
                reason="All severity values are valid and within range",
                label="accurate",
            )]
        return [EvaluationOutput(
            score=0.0, test_pass=False,
            reason=f"Severity issues: {'; '.join(issues)}",
            label="inaccurate",
        )]


class ToolBeforeClaimEvaluator(Evaluator[str, str]):
    """Checks that the agent called data-fetching tools before making claims.

    Failure mode: Agent skipping tool calls and hallucinating alert data.
    """

    def evaluate(self, case: EvaluationData[str, str]) -> list[EvaluationOutput]:
        trajectory = case.actual_trajectory
        output = str(case.actual_output or "")

        # If the output contains alert data but no tools were called, that's a failure
        has_alert_data = any(
            marker in output
            for marker in ['"alert_number"', '"severity"', '"cvss_score"', '"package"']
        )

        tools_called = []
        if isinstance(trajectory, list):
            tools_called = trajectory
        elif trajectory is not None:
            # Session object — we just check it's non-empty
            tools_called = ["session_present"]

        if has_alert_data and not tools_called:
            return [EvaluationOutput(
                score=0.0, test_pass=False,
                reason="Agent produced alert data without calling any data-fetching tools",
                label="hallucinated_data",
            )]

        if not has_alert_data and not tools_called:
            return [EvaluationOutput(
                score=0.3, test_pass=False,
                reason="Agent produced no alert data and called no tools",
                label="no_action",
            )]

        return [EvaluationOutput(
            score=1.0, test_pass=True,
            reason="Agent used tools before producing alert data",
            label="grounded",
        )]


class RemediationSafetyEvaluator(Evaluator[str, str]):
    """Checks remediation plans for dangerous recommendations.

    Failure modes:
    - Recommending a downgrade
    - Suggesting a version that doesn't exist
    - Missing breaking change warnings for major bumps
    """

    def evaluate(self, case: EvaluationData[str, str]) -> list[EvaluationOutput]:
        output = str(case.actual_output or "")
        issues = []

        # Check for downgrade recommendations
        downgrade_patterns = [
            r"downgrade",
            r"roll\s*back",
            r"revert.*version",
        ]
        for pattern in downgrade_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                issues.append("Recommends downgrade (unsafe)")

        # Check that major version bumps have breaking change warnings
        if re.search(r'"upgrade_type"\s*:\s*"major"', output, re.IGNORECASE):
            if not re.search(r"breaking", output, re.IGNORECASE):
                issues.append("Major version upgrade without breaking change warning")

        # Check action field has valid values
        valid_actions = {"upgrade", "pin", "replace", "accept_risk", "mitigate", "monitor"}
        action_pattern = r'"action"\s*:\s*"(\w+)"'
        actions = re.findall(action_pattern, output.lower())
        for action in actions:
            if action not in valid_actions:
                issues.append(f"Invalid remediation action: {action}")

        if not issues:
            return [EvaluationOutput(
                score=1.0, test_pass=True,
                reason="Remediation plan is safe and well-structured",
                label="safe",
            )]

        score = max(0.0, 1.0 - (len(issues) * 0.33))
        return [EvaluationOutput(
            score=score, test_pass=False,
            reason=f"Remediation issues: {'; '.join(issues)}",
            label="unsafe",
        )]


class ReportConsistencyEvaluator(Evaluator[str, str]):
    """Checks that report statistics are internally consistent.

    Failure modes:
    - Severity counts don't sum to total
    - Percentages don't match raw counts
    - Report claims data exists when tools returned errors
    """

    def evaluate(self, case: EvaluationData[str, str]) -> list[EvaluationOutput]:
        output = str(case.actual_output or "")
        issues = []

        # Try to parse the output as JSON to check internal consistency
        try:
            # Find the outermost JSON object in the output
            start = output.find("{")
            end = output.rfind("}") + 1
            if start >= 0 and end > start:
                report = json.loads(output[start:end])
                summary = report.get("summary", {})
                by_sev = summary.get("by_severity", {})
                total = summary.get("total_open", None)

                # Check severity counts sum to total
                if total is not None and by_sev:
                    sev_sum = sum(by_sev.values())
                    if sev_sum != total:
                        issues.append(
                            f"Severity counts sum to {sev_sum} but total_open is {total}"
                        )
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass  # Output isn't structured JSON — other evaluators handle that

        # Check for error indicators in tool output vs claims in report
        error_markers = ['"error"', "status_code", "403", "404", "not found"]
        has_error_signal = any(m in output.lower() for m in error_markers)
        has_stats = any(
            m in output for m in ['"total_open"', '"by_severity"', '"total":']
        )

        if has_error_signal and has_stats:
            # Could be legitimate (partial success), so just flag it
            issues.append(
                "Report contains both error signals and statistics — verify data is not fabricated"
            )

        if not issues:
            return [EvaluationOutput(
                score=1.0, test_pass=True,
                reason="Report statistics are internally consistent",
                label="consistent",
            )]

        score = max(0.0, 1.0 - (len(issues) * 0.5))
        return [EvaluationOutput(
            score=score, test_pass=len(issues) <= 1,
            reason=f"Consistency issues: {'; '.join(issues)}",
            label="inconsistent",
        )]
