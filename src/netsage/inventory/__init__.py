"""Validated, non-secret inventory models."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsage.models import DeviceRef


class UnknownDeviceError(LookupError):
    """Raised when a broker request references no inventory device."""


class Site(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str | None = None


class DeviceGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str | None = None


class Inventory(BaseModel):
    """Inventory index containing only metadata and opaque credential references."""

    model_config = ConfigDict(frozen=True)

    devices: dict[str, DeviceRef] = Field(default_factory=dict)
    sites: dict[str, Site] = Field(default_factory=dict)
    groups: dict[str, DeviceGroup] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        for key, device in self.devices.items():
            if key != device.name:
                raise ValueError(f"device key {key!r} does not match device name {device.name!r}")
            if device.site is not None and device.site not in self.sites:
                raise ValueError(f"device {key!r} references unknown site {device.site!r}")
            unknown_groups = device.groups.difference(self.groups)
            if unknown_groups:
                names = ", ".join(sorted(unknown_groups))
                raise ValueError(f"device {key!r} references unknown groups: {names}")
        return self

    def get_device(self, name: str) -> DeviceRef:
        try:
            return self.devices[name]
        except KeyError as error:
            raise UnknownDeviceError(f"Unknown device: {name}") from error


__all__ = ["DeviceGroup", "Inventory", "Site", "UnknownDeviceError"]
