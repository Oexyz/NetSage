"""Credential isolation contracts.

Credential values are consumed only by trusted connection code and must never be
serialized into AI prompts, evidence, logs, or tool results.
"""

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


class KeyringCredentialProvider(CredentialProvider):
    """Future OS-keychain-backed provider."""

    async def resolve(self, credential_ref: str) -> Credential:
        raise NotImplementedError("Keyring credential resolution is not implemented")


class SSHAgentCredentialProvider(CredentialProvider):
    """Future SSH-agent-backed provider; private keys remain in the agent."""

    async def resolve(self, credential_ref: str) -> Credential:
        raise NotImplementedError("SSH agent credential resolution is not implemented")


class DevelopmentEnvironmentCredentialProvider(CredentialProvider):
    """Explicit local-test provider; never intended for production use."""

    async def resolve(self, credential_ref: str) -> Credential:
        raise NotImplementedError("Development credentials are not implemented")
