"""Closed FortiOS command allowlist."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address


class FortiOSCommand(StrEnum):
    SYSTEM_STATUS = "system_status"
    INTERFACE_CONFIGURATION = "interface_configuration"
    PHYSICAL_INTERFACES = "physical_interfaces"
    ROUTES = "routes"
    ARP_TABLE = "arp_table"
    SYSTEM_HEALTH = "system_health"
    FIREWALL_POLICIES = "firewall_policies"
    PING = "ping"
    TRACEROUTE = "traceroute"


@dataclass(frozen=True, slots=True)
class FortiOSRequest:
    """A typed request which can only render a reviewed command."""

    command: FortiOSCommand
    destination: IPv4Address | IPv6Address | None = None

    def render(self) -> str:
        fixed = {
            FortiOSCommand.SYSTEM_STATUS: "get system status",
            FortiOSCommand.INTERFACE_CONFIGURATION: "show system interface",
            FortiOSCommand.PHYSICAL_INTERFACES: "get system interface physical",
            FortiOSCommand.ROUTES: "get router info routing-table all",
            FortiOSCommand.ARP_TABLE: "get system arp",
            FortiOSCommand.SYSTEM_HEALTH: "get system performance status",
            FortiOSCommand.FIREWALL_POLICIES: "show firewall policy",
        }
        if self.command in fixed:
            if self.destination is not None:
                raise ValueError("destination is not valid for this command")
            return fixed[self.command]
        if self.destination is None:
            raise ValueError("diagnostic command requires an IP destination")
        if self.command is FortiOSCommand.PING:
            return f"execute ping {self.destination}"
        if self.command is FortiOSCommand.TRACEROUTE:
            return f"execute traceroute {self.destination}"
        raise AssertionError("unhandled FortiOS command")
