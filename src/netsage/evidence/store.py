"""In-memory Evidence storage for ephemeral workflows and deterministic tests."""

from typing import Protocol
from uuid import UUID

from netsage.evidence.models import EvidenceEnvelope
from netsage.security import SecretRedactor


class UnsafeEvidenceError(ValueError):
    """Raised when evidence still contains a value recognized as secret material."""


class DuplicateEvidenceError(ValueError):
    pass


class EvidenceNotFoundError(LookupError):
    pass


class EvidenceStore(Protocol):
    def add(self, evidence: EvidenceEnvelope) -> None: ...

    def get(self, evidence_id: UUID) -> EvidenceEnvelope: ...

    def list_for_investigation(self, investigation_id: UUID) -> tuple[EvidenceEnvelope, ...]: ...


class InMemoryEvidenceStore:
    """Store only validated, normalized, secret-free evidence envelopes."""

    def __init__(self, *, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor or SecretRedactor()
        self._evidence: dict[UUID, EvidenceEnvelope] = {}

    def add(self, evidence: EvidenceEnvelope) -> None:
        if not isinstance(evidence, EvidenceEnvelope):
            raise TypeError("evidence store accepts only EvidenceEnvelope values")
        serialized = evidence.model_dump(mode="json")
        if self._redactor.redact(serialized) != serialized:
            raise UnsafeEvidenceError("evidence contains recognized secret material")
        if evidence.evidence_id in self._evidence:
            raise DuplicateEvidenceError("evidence ID already exists")
        self._evidence[evidence.evidence_id] = evidence

    def get(self, evidence_id: UUID) -> EvidenceEnvelope:
        try:
            return self._evidence[evidence_id]
        except KeyError as error:
            raise EvidenceNotFoundError("evidence ID was not found") from error

    def list_for_investigation(self, investigation_id: UUID) -> tuple[EvidenceEnvelope, ...]:
        return tuple(
            evidence
            for evidence in self._evidence.values()
            if evidence.investigation_id == investigation_id
        )
