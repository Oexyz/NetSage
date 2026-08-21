"""Read-only FortiOS driver and trusted SSH transport."""

from netsage.drivers.fortios.catalog import (
    FortiOSCatalogCoverage,
    FortiOSCatalogExecutor,
    FortiOSCommandDefinition,
    FortiOSCommandRegistry,
)
from netsage.drivers.fortios.commands import FortiOSCommand, FortiOSRequest
from netsage.drivers.fortios.driver import (
    FORTIOS_CAPABILITIES,
    FortiOSDriver,
    FortiOSSnapshot,
    FortiOSTransport,
)
from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.transport import (
    FortiOSAuthenticationError,
    FortiOSCommandError,
    FortiOSCommandTimeoutError,
    FortiOSConnectionError,
    FortiOSHostKeyError,
    FortiOSOutputLimitError,
    FortiOSSSHTransport,
    FortiOSTransportError,
    SSHHostKeyPin,
    discover_ssh_host_key,
)

__all__ = [
    "FORTIOS_CAPABILITIES",
    "FortiOSAuthenticationError",
    "FortiOSCatalogCoverage",
    "FortiOSCatalogExecutor",
    "FortiOSCommand",
    "FortiOSCommandDefinition",
    "FortiOSCommandError",
    "FortiOSCommandRegistry",
    "FortiOSCommandTimeoutError",
    "FortiOSConnectionError",
    "FortiOSDriver",
    "FortiOSHostKeyError",
    "FortiOSOutputLimitError",
    "FortiOSParseError",
    "FortiOSRequest",
    "FortiOSSSHTransport",
    "FortiOSSnapshot",
    "FortiOSTransport",
    "FortiOSTransportError",
    "SSHHostKeyPin",
    "discover_ssh_host_key",
]
