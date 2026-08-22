"""Read-only FortiOS driver and trusted SSH transport."""

from netsage.drivers.fortios.catalog import (
    FortiOSCatalogCoverage,
    FortiOSCatalogExecutor,
    FortiOSCommandDefinition,
    FortiOSCommandRegistry,
)
from netsage.drivers.fortios.commands import (
    FortiOSCommand,
    FortiOSRequest,
    FortiOSSemanticCommand,
    FortiOSSemanticRequest,
)
from netsage.drivers.fortios.driver import (
    FORTIOS_CAPABILITIES,
    FortiOSDriver,
    FortiOSSnapshot,
    FortiOSTransport,
)
from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.semantic import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
)
from netsage.drivers.fortios.transport import (
    FortiOSAuthenticationError,
    FortiOSCommandError,
    FortiOSCommandRejectedError,
    FortiOSCommandTimeoutError,
    FortiOSCommandUnavailableError,
    FortiOSConnectionError,
    FortiOSHostKeyError,
    FortiOSOutputLimitError,
    FortiOSPermissionDeniedError,
    FortiOSSSHTransport,
    FortiOSTransportError,
    SSHHostKeyPin,
    discover_ssh_host_key,
)
from netsage.drivers.fortios.variants import (
    FortiOSVariantExhaustedError,
    FortiOSVariantFailure,
    FortiOSVariantOperation,
    FortiOSVariantRegistry,
    SemanticCommandVariant,
)
from netsage.drivers.fortios.version import FortiOSVersion

__all__ = [
    "FORTIOS_CAPABILITIES",
    "FortiOSAuthenticationError",
    "FortiOSCatalogCoverage",
    "FortiOSCatalogExecutor",
    "FortiOSCommand",
    "FortiOSCommandDefinition",
    "FortiOSCommandError",
    "FortiOSCommandRegistry",
    "FortiOSCommandRejectedError",
    "FortiOSCommandTimeoutError",
    "FortiOSCommandUnavailableError",
    "FortiOSConnectionError",
    "FortiOSDriver",
    "FortiOSHostKeyError",
    "FortiOSOutputLimitError",
    "FortiOSParseError",
    "FortiOSPermissionDeniedError",
    "FortiOSRequest",
    "FortiOSSSHTransport",
    "FortiOSSemanticCommand",
    "FortiOSSemanticErrorCategory",
    "FortiOSSemanticParseError",
    "FortiOSSemanticRequest",
    "FortiOSSnapshot",
    "FortiOSTransport",
    "FortiOSTransportError",
    "FortiOSVariantExhaustedError",
    "FortiOSVariantFailure",
    "FortiOSVariantOperation",
    "FortiOSVariantRegistry",
    "FortiOSVersion",
    "SSHHostKeyPin",
    "SemanticCommandVariant",
    "discover_ssh_host_key",
]
