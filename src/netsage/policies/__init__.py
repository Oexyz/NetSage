"""Authorization policies for structured broker operations."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class OperationClass(StrEnum):
    READ_ONLY = "read_only"
    DIAGNOSTIC = "diagnostic"
    CONFIGURATION = "configuration"
    DESTRUCTIVE = "destructive"


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str


class ObservePolicy:
    """Default policy: reads only, with optional named diagnostics."""

    def __init__(self, *, allowed_diagnostics: frozenset[str] = frozenset()) -> None:
        self._allowed_diagnostics = allowed_diagnostics

    def authorize(self, tool: str, operation_class: OperationClass) -> AuthorizationDecision:
        if operation_class is OperationClass.READ_ONLY:
            return AuthorizationDecision(allowed=True, reason="read-only operation allowed")
        if operation_class is OperationClass.DIAGNOSTIC and tool in self._allowed_diagnostics:
            return AuthorizationDecision(allowed=True, reason="diagnostic explicitly allowed")
        if operation_class is OperationClass.DIAGNOSTIC:
            return AuthorizationDecision(allowed=False, reason="diagnostic not allowed by policy")
        return AuthorizationDecision(
            allowed=False,
            reason=f"{operation_class.value} operations are denied in observe mode",
        )


__all__ = ["AuthorizationDecision", "ObservePolicy", "OperationClass"]
