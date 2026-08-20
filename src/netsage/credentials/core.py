"""Credential isolation contracts and process-memory-only implementation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum


class CredentialKind(StrEnum):
    PASSWORD = "password"  # noqa: S105 - credential type label, not a secret
    SSH_AGENT = "ssh_agent"
    API_TOKEN = "api_token"  # noqa: S105 - credential type label, not a secret


@dataclass(frozen=True, slots=True, repr=False)
class Credential:
    """Opaque-to-the-AI credential material for the trusted connection layer."""

    username: str | None
    secret: str | None
    kind: CredentialKind


class CredentialProvider(ABC):
    """Resolve a named credential inside the trusted boundary."""

    @abstractmethod
    async def resolve(self, credential_ref: str) -> Credential: ...


class EphemeralCredentialProvider(CredentialProvider):
    """Hold one credential in process memory only for a bounded live operation."""

    def __init__(self, credential_ref: str, credential: Credential) -> None:
        self._credential_ref = credential_ref
        self._credential = credential

    async def resolve(self, credential_ref: str) -> Credential:
        if credential_ref != self._credential_ref:
            raise LookupError("Unknown ephemeral credential reference")
        return self._credential


class SSHAgentCredentialProvider(CredentialProvider):
    """Future SSH-agent-backed provider; private keys remain in the agent."""

    async def resolve(self, credential_ref: str) -> Credential:
        raise NotImplementedError("SSH agent credential resolution is not implemented")


class DevelopmentEnvironmentCredentialProvider(CredentialProvider):
    """Explicit local-test provider; never intended for production use."""

    async def resolve(self, credential_ref: str) -> Credential:
        raise NotImplementedError("Development credentials are not implemented")
