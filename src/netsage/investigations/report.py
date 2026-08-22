"""Human-readable rendering for deterministic investigation reports."""

from netsage.investigations.models import DiagnosisStrength, InvestigationReport


def render_investigation_report(report: InvestigationReport) -> str:
    lines = [
        "HA Diagnosis" if report.ha_summary is not None else "FortiGate Investigation",
        "",
        "Device:",
        report.investigation.device_id,
        "",
        "Status:",
        report.status.value.upper(),
        "",
        "Evidence collected:",
        str(len(report.evidence_ids)),
    ]
    if report.ha_summary is not None:
        summary = report.ha_summary
        lines.extend(
            (
                "",
                "Synchronization:",
                summary.synchronization.value.replace("_", " ").upper(),
                "",
                "Observed incidents:",
                f"{summary.incident_count} correlated HA incident episode(s)",
                "",
                "Fault domain:",
                ", ".join(domain.value.replace("_", " ") for domain in summary.fault_domains),
                "",
                "Correlation strength:",
                summary.strength.value.upper(),
                "",
                "Specific physical cause:",
                "NOT CONFIRMED",
            )
        )
    lines.extend(("", "Findings:"))
    if report.findings:
        for index, finding in enumerate(report.findings, start=1):
            lines.extend(
                (
                    "",
                    f"{index}. {finding.title}",
                    f"   {finding.severity.value.upper()}",
                    *(
                        (f"   Strength: {finding.strength.value.upper()}",)
                        if finding.strength is not None
                        else ()
                    ),
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
