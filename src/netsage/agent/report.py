"""Render deterministic findings and AI assessment as separate sections."""

from netsage.agent.models import AgentInvestigationReport


def render_agent_report(report: AgentInvestigationReport) -> str:
    lines = [
        "NetSage AI Investigation",
        "",
        "Device:",
        report.device_id,
        "",
        "Provider:",
        report.provider,
        "",
        "Deterministic findings:",
    ]
    if report.deterministic_findings:
        lines.extend(f"- {item.summary}" for item in report.deterministic_findings)
    else:
        lines.append("None.")
    lines.extend(("", "AI assessment:"))
    if report.ai_assessment is None:
        lines.append("No validated AI assessment is available.")
        if report.error_category is not None:
            lines.append(f"Runtime result: {report.error_category.value}")
        if report.provider_error_code is not None:
            lines.append(f"Provider result: {report.provider_error_code}")
    else:
        lines.append(report.ai_assessment.summary)
        lines.extend(("", "Strength:", report.ai_assessment.diagnosis_strength.value.upper()))
        lines.extend(("", "Evidence:"))
        lines.extend(f"- {item}" for item in report.ai_assessment.evidence_ids)
        if report.ai_assessment.limitations:
            lines.extend(("", "Limitations:"))
            lines.extend(f"- {item}" for item in report.ai_assessment.limitations)
    lines.extend(("", "No configuration changes were made."))
    return "\n".join(lines)
