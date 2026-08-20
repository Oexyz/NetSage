"""Persistent SSH fingerprint trust with rediscovery before authentication."""

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsage.drivers.fortios import SSHHostKeyPin, discover_ssh_host_key
from netsage.models import CredentialReference
from netsage.state.atomic import load_yaml_document, save_yaml_document


class SSHHostTrustRecord(BaseModel):
    """Non-secret host identity; public key bodies are intentionally not persisted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    host: str = Field(min_length=1, max_length=512)
    port: int = Field(ge=1, le=65535)
    algorithm: str = Field(min_length=1, max_length=128)
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/=]+$")

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        CredentialReference(self.name)
        if "@" in self.host:
            raise ValueError("host must not contain embedded credentials")
        return self


class SSHHostTrustDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    hosts: dict[str, SSHHostTrustRecord] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_host_keys(self) -> Self:
        for key, record in self.hosts.items():
            if key != record.name:
                raise ValueError("SSH trust key does not match trust record name")
        return self


class SSHTrustError(RuntimeError):
    pass


class SSHTrustNotFoundError(SSHTrustError):
    pass


class DuplicateSSHTrustError(SSHTrustError):
    pass


class SSHTrustBindingError(SSHTrustError):
    pass


class SSHHostIdentityChangedError(SSHTrustError):
    def __init__(
        self,
        *,
        expected_algorithm: str,
        expected_fingerprint: str,
        received_algorithm: str,
        received_fingerprint: str,
    ) -> None:
        super().__init__("SSH host key changed; connection aborted")
        self.expected_algorithm = expected_algorithm
        self.expected_fingerprint = expected_fingerprint
        self.received_algorithm = received_algorithm
        self.received_fingerprint = received_fingerprint


class SSHHostTrustStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def initialize(self) -> None:
        if not self._path.exists():
            self.save(SSHHostTrustDocument())

    def load(self) -> SSHHostTrustDocument:
        return load_yaml_document(self._path, SSHHostTrustDocument)

    def save(self, document: SSHHostTrustDocument) -> None:
        save_yaml_document(self._path, document)

    def get(self, name: str) -> SSHHostTrustRecord:
        try:
            return self.load().hosts[name]
        except KeyError as error:
            raise SSHTrustNotFoundError(f"SSH trust record not found: {name}") from error

    def add(self, record: SSHHostTrustRecord) -> SSHHostTrustDocument:
        document = self.load()
        if record.name in document.hosts:
            raise DuplicateSSHTrustError(f"SSH trust record already exists: {record.name}")
        updated = SSHHostTrustDocument(hosts={**document.hosts, record.name: record})
        self.save(updated)
        return updated

    def replace(self, record: SSHHostTrustRecord) -> SSHHostTrustDocument:
        document = self.load()
        if record.name not in document.hosts:
            raise SSHTrustNotFoundError(f"SSH trust record not found: {record.name}")
        hosts = {**document.hosts, record.name: record}
        updated = SSHHostTrustDocument(hosts=hosts)
        self.save(updated)
        return updated

    def remove(self, name: str, *, missing_ok: bool = False) -> None:
        document = self.load()
        if name not in document.hosts:
            if missing_ok:
                return
            raise SSHTrustNotFoundError(f"SSH trust record not found: {name}")
        hosts = dict(document.hosts)
        del hosts[name]
        self.save(SSHHostTrustDocument(hosts=hosts))


HostKeyDiscovery = Callable[[str, int], Awaitable[SSHHostKeyPin]]


class SSHHostTrustManager:
    """Rediscover public host keys and compare persistent fingerprints before auth."""

    def __init__(
        self,
        store: SSHHostTrustStore,
        *,
        discovery: HostKeyDiscovery = discover_ssh_host_key,
    ) -> None:
        self._store = store
        self._discovery = discovery

    async def discover(self, host: str, port: int) -> SSHHostKeyPin:
        return await self._discovery(host, port)

    def trust_first(
        self,
        *,
        name: str,
        host: str,
        port: int,
        pin: SSHHostKeyPin,
    ) -> SSHHostTrustRecord:
        record = self._record(name=name, host=host, port=port, pin=pin)
        self._store.add(record)
        return record

    async def verify(self, *, name: str, host: str, port: int) -> SSHHostKeyPin:
        record = self._store.get(name)
        if record.host != host or record.port != port:
            raise SSHTrustBindingError("SSH trust record does not match device address")
        pin = await self.discover(host, port)
        if record.algorithm != pin.algorithm or record.fingerprint != pin.fingerprint:
            raise SSHHostIdentityChangedError(
                expected_algorithm=record.algorithm,
                expected_fingerprint=record.fingerprint,
                received_algorithm=pin.algorithm,
                received_fingerprint=pin.fingerprint,
            )
        return pin

    def replace(self, *, name: str, host: str, port: int, pin: SSHHostKeyPin) -> None:
        self._store.replace(self._record(name=name, host=host, port=port, pin=pin))

    @staticmethod
    def _record(*, name: str, host: str, port: int, pin: SSHHostKeyPin) -> SSHHostTrustRecord:
        return SSHHostTrustRecord(
            name=name,
            host=host,
            port=port,
            algorithm=pin.algorithm,
            fingerprint=pin.fingerprint,
        )
