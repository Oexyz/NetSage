"""Pure FortiOS semantic parsers and normalized summaries."""

from netsage.drivers.fortios.semantic.bgp import (
    parse_bgp_neighbors_status,
    parse_bgp_status,
)
from netsage.drivers.fortios.semantic.common import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
)
from netsage.drivers.fortios.semantic.ha import parse_ha_status
from netsage.drivers.fortios.semantic.ha_checksum import parse_ha_checksum_nonsync
from netsage.drivers.fortios.semantic.ha_history import parse_ha_history
from netsage.drivers.fortios.semantic.ipsec import parse_ipsec_status
from netsage.drivers.fortios.semantic.ospf import parse_ospf_status
from netsage.drivers.fortios.semantic.routing import summarize_routes
from netsage.drivers.fortios.semantic.sdwan import parse_sdwan_status

__all__ = [
    "FortiOSSemanticErrorCategory",
    "FortiOSSemanticParseError",
    "parse_bgp_neighbors_status",
    "parse_bgp_status",
    "parse_ha_checksum_nonsync",
    "parse_ha_history",
    "parse_ha_status",
    "parse_ipsec_status",
    "parse_ospf_status",
    "parse_sdwan_status",
    "summarize_routes",
]
