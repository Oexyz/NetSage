"""Safe device readiness results for local onboarding and connection testing."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from netsage.models import DeviceFacts


class CheckStatus(StrEnum):
    PASS = "pass"  # noqa: S105 - check result label, not a credential
    FAIL = "fail"
    NOT_RUN = "not_run"


class DeviceReadiness(StrEnum):
    READY = "ready"
    UNREACHABLE = "unreachable"
    HOST_KEY_ERROR = "host_key_error"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    AUTHENTICATION_FAILED = "authentication_failed"
    FORTIOS_UNVERIFIED = "fortios_unverified"
    FAILED = "failed"


class DeviceTestResult(BaseModel):
    """Bounded status categories; no raw exception, credential, or device output."""

    model_config = ConfigDict(frozen=True)

    device_id: str
    readiness: DeviceReadiness
    configured: CheckStatus = CheckStatus.NOT_RUN
    reachable: CheckStatus = CheckStatus.NOT_RUN
    host_key: CheckStatus = CheckStatus.NOT_RUN
    credential: CheckStatus = CheckStatus.NOT_RUN
    authentication: CheckStatus = CheckStatus.NOT_RUN
    fortios: CheckStatus = CheckStatus.NOT_RUN
    facts: CheckStatus = CheckStatus.NOT_RUN
    device_facts: DeviceFacts | None = None
    expected_host_key: str | None = None
    received_host_key: str | None = None
    detail: str
