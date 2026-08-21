"""Composition root for versioned, non-secret local application state."""

from netsage.credentials import CredentialProfileStore
from netsage.history import HistoryDatabase
from netsage.inventory import Inventory
from netsage.inventory.store import InventoryStore
from netsage.state.atomic import load_yaml_document, save_yaml_document
from netsage.state.documents import ApplicationSettingsDocument
from netsage.state.paths import StatePaths
from netsage.state.trust import SSHHostTrustStore


class InvalidStateReferenceError(RuntimeError):
    pass


class ApplicationSettingsStore:
    def __init__(self, paths: StatePaths) -> None:
        self._path = paths.settings

    def initialize(self) -> None:
        if not self._path.exists():
            save_yaml_document(self._path, ApplicationSettingsDocument())

    def load(self) -> ApplicationSettingsDocument:
        return load_yaml_document(self._path, ApplicationSettingsDocument)


class LocalState:
    """Small facade over separate settings, inventory, credential, and trust stores."""

    def __init__(self, paths: StatePaths | None = None) -> None:
        self.paths = paths or StatePaths.default()
        self.settings = ApplicationSettingsStore(self.paths)
        self.inventory = InventoryStore(self.paths.inventory)
        self.credentials = CredentialProfileStore(self.paths.credential_profiles)
        self.host_trust = SSHHostTrustStore(self.paths.host_trust)
        self.history = HistoryDatabase(self.paths.history)

    def initialize(self) -> None:
        self.settings.initialize()
        self.inventory.initialize()
        self.credentials.initialize()
        self.host_trust.initialize()
        self.history.initialize()
        self.settings.load()
        self.inventory.load()
        self.credentials.load()
        self.host_trust.load()
        self.history.quick_check()

    def load_inventory(self) -> Inventory:
        inventory = self.inventory.load()
        profiles = self.credentials.load().profiles
        hosts = self.host_trust.load().hosts
        for device in inventory.devices.values():
            credential_ref = str(device.credential_ref)
            if credential_ref not in profiles:
                raise InvalidStateReferenceError(
                    f"Device {device.name} references missing credential profile: {credential_ref}"
                )
            if device.trust_ref is None:
                raise InvalidStateReferenceError(f"Device {device.name} has no SSH trust reference")
            try:
                trust = hosts[device.trust_ref]
            except KeyError as error:
                raise InvalidStateReferenceError(
                    f"Device {device.name} references missing SSH trust: {device.trust_ref}"
                ) from error
            if trust.host != device.host or trust.port != device.port:
                raise InvalidStateReferenceError(
                    f"Device {device.name} SSH trust does not match its address"
                )
        return inventory
