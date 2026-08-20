"""Atomic YAML persistence for the existing frozen Inventory domain."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from netsage.inventory.models import DeviceGroup, Inventory, Site
from netsage.models import DeviceRef
from netsage.state.atomic import load_yaml_document, save_yaml_document


class DuplicateDeviceError(ValueError):
    pass


class InventoryDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    devices: dict[str, DeviceRef] = Field(default_factory=dict)
    sites: dict[str, Site] = Field(default_factory=dict)
    groups: dict[str, DeviceGroup] = Field(default_factory=dict)

    @classmethod
    def from_inventory(cls, inventory: Inventory) -> "InventoryDocument":
        return cls(devices=inventory.devices, sites=inventory.sites, groups=inventory.groups)

    def to_inventory(self) -> Inventory:
        return Inventory(devices=self.devices, sites=self.sites, groups=self.groups)


class InventoryStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def initialize(self) -> None:
        if not self._path.exists():
            self.save(Inventory())

    def load(self) -> Inventory:
        return load_yaml_document(self._path, InventoryDocument).to_inventory()

    def save(self, inventory: Inventory) -> None:
        save_yaml_document(self._path, InventoryDocument.from_inventory(inventory))

    def add(self, device: DeviceRef) -> Inventory:
        inventory = self.load()
        if device.name in inventory.devices:
            raise DuplicateDeviceError(f"Device already exists: {device.name}")
        devices = {**inventory.devices, device.name: device}
        updated = Inventory(devices=devices, sites=inventory.sites, groups=inventory.groups)
        self.save(updated)
        return updated

    def remove(self, name: str) -> tuple[Inventory, DeviceRef]:
        inventory = self.load()
        device = inventory.get_device(name)
        devices = dict(inventory.devices)
        del devices[name]
        updated = Inventory(devices=devices, sites=inventory.sites, groups=inventory.groups)
        self.save(updated)
        return updated, device
