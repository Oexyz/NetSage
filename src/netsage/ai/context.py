"""Explicit allowlisted construction of provider-visible investigation context."""

from collections.abc import Sequence

from netsage.ai.models import AIContext, AIDeviceContext, AIEvidence, AIFinding
from netsage.evidence import EvidenceEnvelope
from netsage.investigations import InvestigationReport
from netsage.models import DeviceRef
from netsage.security import SecretRedactor


class UnsafeAIContextError(ValueError):
    pass


class AIContextBuilder:
    def __init__(self, *, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor or SecretRedactor()

    def build(
        self,
        *,
        user_request: str,
        device: DeviceRef,
        report: InvestigationReport,
        evidence: Sequence[EvidenceEnvelope],
    ) -> AIContext:
        context = AIContext(
            investigation_id=report.investigation.investigation_id,
            user_request=user_request,
            device=AIDeviceContext(
                device_id=device.name,
                platform=device.platform,
                capabilities=tuple(sorted(device.capabilities, key=lambda item: item.value)),
            ),
            evidence=tuple(
                AIEvidence(
                    evidence_id=item.evidence_id,
                    source_device=item.device_id,
                    operation=item.operation,
                    capability=item.capability,
                    observed_at=item.observed_at,
                    trust=item.trust,
                    payload=item.payload,
                )
                for item in evidence
            ),
            deterministic_findings=tuple(
                AIFinding(
                    code=item.code,
                    title=item.title,
                    summary=item.summary,
                    severity=item.severity,
                    strength=item.strength,
                    evidence_ids=item.evidence_ids,
                )
                for item in report.findings
            ),
            missing_evidence=(
                report.diagnosis.missing_evidence if report.diagnosis is not None else ()
            ),
        )
        serialized = context.model_dump(mode="json")
        if self._redactor.redact(serialized) != serialized:
            raise UnsafeAIContextError("AI context contains recognized secret material")
        return context
