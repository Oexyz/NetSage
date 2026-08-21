"""Read-only FortiOS driver and trusted SSH transport."""

from netsage.drivers.fortios.catalog import (
    FortiOSCatalogCoverage,
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
    FortiOSConnectionError,
    FortiOSHostKeyError,
    FortiOSSSHTransport,
    FortiOSTransportError,
    SSHHostKeyPin,
    discover_ssh_host_key,
)

__all__ = [
    "FORTIOS_CAPABILITIES",
    "FortiOSAuthenticationError",
    "FortiOSCatalogCoverage",
    "FortiOSCommand",
    "FortiOSCommandDefinition",
    "FortiOSCommandError",
    "FortiOSCommandRegistry",
    "FortiOSConnectionError",
    "FortiOSDriver",
    "FortiOSHostKeyError",
    "FortiOSParseError",
    "FortiOSRequest",
    "FortiOSSSHTransport",
    "FortiOSSnapshot",
    "FortiOSTransport",
    "FortiOSTransportError",
    "SSHHostKeyPin",
    "discover_ssh_host_key",
]
