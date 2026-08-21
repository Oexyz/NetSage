"""Lazy, read-only access to the generated FortiOS command manifest."""

from __future__ import annotations

import gzip
import re
from collections.abc import Mapping
from functools import lru_cache
from importlib.resources import files
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from pydantic import TypeAdapter, ValidationError

from netsage.drivers.fortios.catalog.models import (
    FortiOSArgumentDefinition,
    FortiOSArgumentKind,
    FortiOSCommandDefinition,
    FortiOSCommandManifest,
)

_MANIFEST_NAME = "fortios_7_2_13.json.gz"
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@,+%-]{0,511}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_PROTOCOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
_MAC_ADDRESS = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_INTEGER_ADAPTER: TypeAdapter[int] = TypeAdapter(int)


class FortiOSCatalogError(RuntimeError):
    pass


class UnknownFortiOSCommandError(FortiOSCatalogError):
    pass


class FortiOSCommandRenderError(FortiOSCatalogError):
    pass


class FortiOSCommandArgumentError(FortiOSCommandRenderError):
    pass


class FortiOSCommandRegistry:
    def __init__(self, manifest: FortiOSCommandManifest | None = None) -> None:
        self._manifest = manifest or load_manifest()
        self._by_id = {definition.id: definition for definition in self._manifest.definitions}

    @property
    def manifest(self) -> FortiOSCommandManifest:
        return self._manifest

    def get(self, command_id: str) -> FortiOSCommandDefinition:
        try:
            return self._by_id[command_id]
        except KeyError as error:
            raise UnknownFortiOSCommandError("Unknown FortiOS command ID") from error

    def search(self, query: str, *, limit: int = 50) -> tuple[FortiOSCommandDefinition, ...]:
        normalized = query.strip().casefold()
        if not normalized:
            raise ValueError("FortiOS command search query must not be blank")
        if limit < 1 or limit > 1000:
            raise ValueError("FortiOS command search limit must be between 1 and 1000")
        matches = (
            definition
            for definition in self._manifest.definitions
            if normalized
            in " ".join(
                (
                    definition.id,
                    definition.path,
                    definition.syntax,
                    definition.scope or "",
                    definition.capability.value if definition.capability else "",
                )
            ).casefold()
        )
        return tuple(list(matches)[:limit])

    def render(self, command_id: str, arguments: Mapping[str, object]) -> str:
        definition = self.get(command_id)
        if not definition.renderable:
            raise FortiOSCommandRenderError("FortiOS command syntax is not safely renderable")
        expected = {argument.name for argument in definition.arguments}
        supplied = set(arguments)
        missing = {
            argument.name
            for argument in definition.arguments
            if argument.required and argument.name not in supplied
        }
        if missing or not supplied.issubset(expected):
            raise FortiOSCommandArgumentError("FortiOS command arguments do not match definition")
        rendered = definition.syntax
        for argument in definition.arguments:
            if argument.name not in arguments:
                rendered = rendered.replace(argument.placeholder, "", 1)
                continue
            value = _render_argument(argument, arguments[argument.name])
            rendered = rendered.replace(argument.placeholder, value, 1)
        rendered = re.sub(r"\s+", " ", rendered).strip()
        if any(character in rendered for character in ("\n", "\r", "\x00")):
            raise FortiOSCommandRenderError("FortiOS rendered command contains control data")
        return rendered


@lru_cache(maxsize=1)
def load_manifest() -> FortiOSCommandManifest:
    resource = files("netsage.drivers.fortios.catalog.generated").joinpath(_MANIFEST_NAME)
    try:
        compressed = resource.read_bytes()
        payload = gzip.decompress(compressed)
        return FortiOSCommandManifest.model_validate_json(payload)
    except (OSError, EOFError, ValidationError, ValueError) as error:
        raise FortiOSCatalogError("FortiOS command manifest is unavailable or invalid") from error


def _render_argument(argument: FortiOSArgumentDefinition, value: object) -> str:
    if argument.sensitive:
        raise FortiOSCommandArgumentError("Sensitive FortiOS arguments cannot be rendered")
    if argument.kind in {FortiOSArgumentKind.INTEGER, FortiOSArgumentKind.POLICY_ID}:
        try:
            integer = _INTEGER_ADAPTER.validate_python(value)
        except ValidationError as error:
            raise FortiOSCommandArgumentError("FortiOS integer argument is invalid") from error
        _validate_numeric_bounds(argument, integer)
        return str(integer)
    if argument.kind is FortiOSArgumentKind.PORT:
        try:
            port = _INTEGER_ADAPTER.validate_python(value)
        except ValidationError as error:
            raise FortiOSCommandArgumentError("FortiOS port argument is invalid") from error
        _validate_numeric_bounds(argument, port)
        return str(port)
    text = str(value)
    if argument.kind is FortiOSArgumentKind.IPV4_ADDRESS:
        try:
            parsed = ip_address(text)
        except ValueError as error:
            raise FortiOSCommandArgumentError("FortiOS IPv4 argument is invalid") from error
        if not isinstance(parsed, IPv4Address):
            raise FortiOSCommandArgumentError("FortiOS IPv4 argument is invalid")
        return str(parsed)
    if argument.kind is FortiOSArgumentKind.IPV6_ADDRESS:
        try:
            parsed = ip_address(text)
        except ValueError as error:
            raise FortiOSCommandArgumentError("FortiOS IPv6 argument is invalid") from error
        if not isinstance(parsed, IPv6Address):
            raise FortiOSCommandArgumentError("FortiOS IPv6 argument is invalid")
        return str(parsed)
    if argument.kind is FortiOSArgumentKind.IP_ADDRESS:
        try:
            return str(ip_address(text))
        except ValueError as error:
            raise FortiOSCommandArgumentError("FortiOS IP argument is invalid") from error
    if argument.kind is FortiOSArgumentKind.NETWORK:
        try:
            return str(ip_network(text, strict=False))
        except ValueError as error:
            raise FortiOSCommandArgumentError("FortiOS network argument is invalid") from error
    if argument.kind in {FortiOSArgumentKind.ENUM, FortiOSArgumentKind.BOOLEAN}:
        if text not in argument.choices:
            raise FortiOSCommandArgumentError("FortiOS enum argument is invalid")
        return text
    if argument.kind is FortiOSArgumentKind.HOSTNAME:
        if len(text) > 253 or not all(
            label
            and len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in text.rstrip(".").split(".")
        ):
            raise FortiOSCommandArgumentError("FortiOS hostname argument is invalid")
        return text
    if argument.kind in {FortiOSArgumentKind.INTERFACE, FortiOSArgumentKind.VDOM}:
        if not _SAFE_IDENTIFIER.fullmatch(text):
            raise FortiOSCommandArgumentError("FortiOS identifier argument is invalid")
        return text
    if argument.kind is FortiOSArgumentKind.PROTOCOL:
        if not _SAFE_PROTOCOL.fullmatch(text):
            raise FortiOSCommandArgumentError("FortiOS protocol argument is invalid")
        return text
    if argument.kind is FortiOSArgumentKind.MAC_ADDRESS:
        normalized = text.replace("-", ":").lower()
        if not _MAC_ADDRESS.fullmatch(normalized):
            raise FortiOSCommandArgumentError("FortiOS MAC address argument is invalid")
        return normalized
    if not _SAFE_TOKEN.fullmatch(text):
        raise FortiOSCommandArgumentError("FortiOS string argument contains unsafe characters")
    return text


def _validate_numeric_bounds(argument: FortiOSArgumentDefinition, value: int) -> None:
    minimum = 0 if argument.minimum is None else argument.minimum
    if value < minimum or (argument.maximum is not None and value > argument.maximum):
        raise FortiOSCommandArgumentError("FortiOS numeric argument is out of range")
