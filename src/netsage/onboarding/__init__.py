"""FortiOS-only secure local device onboarding and runtime composition."""

from netsage.onboarding.models import CheckStatus, DeviceReadiness, DeviceTestResult
from netsage.onboarding.runtime import FortiOSRuntimeFactory, PreparedFortiOSRuntime
from netsage.onboarding.service import (
    DeviceOnboardingError,
    FortiOSDeviceService,
    InvestigationHistoryWriteError,
)

__all__ = [
    "CheckStatus",
    "DeviceOnboardingError",
    "DeviceReadiness",
    "DeviceTestResult",
    "FortiOSDeviceService",
    "FortiOSRuntimeFactory",
    "InvestigationHistoryWriteError",
    "PreparedFortiOSRuntime",
]
