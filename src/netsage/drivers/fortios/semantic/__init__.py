"""Pure FortiOS semantic parsers and normalized summaries."""

from netsage.drivers.fortios.semantic.bgp import parse_bgp_status
from netsage.drivers.fortios.semantic.ha import parse_ha_status
from netsage.drivers.fortios.semantic.ipsec import parse_ipsec_status
from netsage.drivers.fortios.semantic.ospf import parse_ospf_status
from netsage.drivers.fortios.semantic.routing import summarize_routes
from netsage.drivers.fortios.semantic.sdwan import parse_sdwan_status

__all__ = [
    "parse_bgp_status",
    "parse_ha_status",
    "parse_ipsec_status",
    "parse_ospf_status",
    "parse_sdwan_status",
    "summarize_routes",
]
