"""Closed FortiOS command allowlist."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from netsage.policies import OperationClass


class FortiOSCommand(StrEnum):
    SYSTEM_STATUS = "system_status"
    INTERFACE_CONFIGURATION = "interface_configuration"
    PHYSICAL_INTERFACES = "physical_interfaces"
    ROUTES = "routes"
    ARP_TABLE = "arp_table"
    SYSTEM_HEALTH = "system_health"
    FIREWALL_POLICIES = "firewall_policies"
    HA_STATUS = "ha_status"
    SDWAN_MEMBERS = "sdwan_members"
    BGP_SUMMARY = "bgp_summary"
    BGP_NEIGHBORS = "bgp_neighbors"
    OSPF_STATUS = "ospf_status"
    OSPF_NEIGHBORS = "ospf_neighbors"
    OSPF_NEIGHBORS_LEGACY = "ospf_neighbors_legacy"
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
            FortiOSCommand.HA_STATUS: "get system ha status",
            FortiOSCommand.SDWAN_MEMBERS: "diagnose sys sdwan member",
            FortiOSCommand.BGP_SUMMARY: "get router info bgp summary",
            FortiOSCommand.BGP_NEIGHBORS: "get router info bgp neighbors",
            FortiOSCommand.OSPF_STATUS: "get router info ospf status",
            FortiOSCommand.OSPF_NEIGHBORS: "get router info ospf neighbor all",
            FortiOSCommand.OSPF_NEIGHBORS_LEGACY: "get router info ospf neighbor",
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


class FortiOSSemanticCommand(StrEnum):
    """Source-traceable read-only catalog definitions promoted only semantically."""

    HA_HISTORY = "fortios.diagnose.sys.ha.history.read"
    HA_CHECKSUM_NONSYNC = "fortios.diagnose.sys.ha.checksum.show-nonsync"
    SDWAN_HEALTH_CHECKS = "fortios.diagnose.sys.sdwan.health-check"
    IPSEC_PHASE1 = "fortios.diagnose.vpn.ike.gateway.list"
    IPSEC_TUNNELS = "fortios.diagnose.vpn.tunnel.list"


@dataclass(frozen=True, slots=True)
class FortiOSSemanticRequest:
    """A fixed reviewed Catalog ID with no caller-controlled command or arguments."""

    command: FortiOSSemanticCommand

    def render(self) -> str:
        from netsage.drivers.fortios.catalog import FortiOSCommandRegistry

        registry = FortiOSCommandRegistry()
        definition = registry.get(self.command.value)
        if (
            definition.command_class is not OperationClass.READ_ONLY
            or not definition.renderable
            or definition.arguments
        ):
            raise ValueError("FortiOS semantic catalog command is not safely renderable")
        return registry.render(definition.id, {})
