"""Human-readable rendering for deterministic investigation reports."""

from netsage.investigations.models import DiagnosisStrength, InvestigationReport


def render_investigation_report(report: InvestigationReport) -> str:
    lines = [
        "FortiGate Investigation",
        "",
        "Device:",
        report.investigation.device_id,
        "",
        "Status:",
        report.status.value.upper(),
        "",
        "Evidence collected:",
        str(len(report.evidence_ids)),
        "",
        "Findings:",
    ]
    if report.findings:
        for index, finding in enumerate(report.findings, start=1):
            lines.extend(
                (
                    "",
                    f"{index}. {finding.title}",
                    f"   {finding.severity.value.upper()}",
                    f"   {finding.summary}",
                )
            )
    else:
        lines.extend(("", "None."))
    lines.extend(("", "Diagnosis:"))
    if report.diagnosis is None:
        lines.extend(
            (
                "No single root cause identified.",
                "",
                "Strength:",
                DiagnosisStrength.INSUFFICIENT.value.upper(),
            )
        )
    else:
        lines.extend(
            (
                report.diagnosis.summary,
                "",
                "Strength:",
                report.diagnosis.strength.value.upper(),
            )
        )
        if report.diagnosis.missing_evidence:
            lines.extend(("", "Missing evidence:"))
            lines.extend(f"- {item}" for item in report.diagnosis.missing_evidence)
    lines.extend(("", "No configuration changes were made."))
    return "\n".join(lines)
