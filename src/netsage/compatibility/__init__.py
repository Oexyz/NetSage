"""Typed compatibility characterization and safe report export."""

from netsage.compatibility.export import (
    CompatibilityExportError,
    export_compatibility_report,
)
from netsage.compatibility.models import (
    COMPATIBILITY_REPORT_SCHEMA_VERSION,
    CapabilityObservationState,
    CompatibilityArea,
    CompatibilityAreaResult,
    CompatibilityErrorCategory,
    CompatibilityParserState,
    FortiOSCompatibilityReport,
    FortiOSVDOMContext,
    FortiOSVDOMMode,
    FortiOSVDOMProfile,
)
from netsage.compatibility.probe import (
    FortiOSCompatibilityProbe,
    failed_compatibility_report,
)
from netsage.compatibility.service import FortiOSCompatibilityService

__all__ = [
    "COMPATIBILITY_REPORT_SCHEMA_VERSION",
    "CapabilityObservationState",
    "CompatibilityArea",
    "CompatibilityAreaResult",
    "CompatibilityErrorCategory",
    "CompatibilityExportError",
    "CompatibilityParserState",
    "FortiOSCompatibilityProbe",
    "FortiOSCompatibilityReport",
    "FortiOSCompatibilityService",
    "FortiOSVDOMContext",
    "FortiOSVDOMMode",
    "FortiOSVDOMProfile",
    "export_compatibility_report",
    "failed_compatibility_report",
]
