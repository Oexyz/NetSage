"""Derive bounded route-table semantics without additional device commands."""

from collections.abc import Sequence

from netsage.models import Route, RouteSummary


def summarize_routes(device_id: str, routes: Sequence[Route]) -> RouteSummary:
    defaults = tuple(route for route in routes if route.prefix.prefixlen == 0)
    active_defaults = tuple(route for route in defaults if route.active)
    return RouteSummary(
        device_id=device_id,
        total_routes=len(routes),
        active_routes=sum(route.active for route in routes),
        default_routes=len(defaults),
        active_default_routes=len(active_defaults),
        equal_cost_default_routes=len(active_defaults) > 1,
        protocols=tuple(sorted({route.protocol for route in routes})),
    )
