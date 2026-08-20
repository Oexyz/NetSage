"""Serializable credential metadata which never contains secret material."""

from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsage.credentials.core import CredentialKind
from netsage.models import CredentialReference
from netsage.state.atomic import load_yaml_document, save_yaml_document


class CredentialProviderType(StrEnum):
    KEYRING = "keyring"


class CredentialProfile(BaseModel):
    """Persistent provider, kind, and username metadata; never a Credential."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    provider: CredentialProviderType = CredentialProviderType.KEYRING
    kind: CredentialKind = CredentialKind.PASSWORD
    username: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        CredentialReference(self.name)
        if not self.username.strip():
            raise ValueError("credential profile username must not be blank")
        if self.kind is not CredentialKind.PASSWORD:
            raise ValueError("only password credential profiles are supported")
        return self


class CredentialProfilesDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    profiles: dict[str, CredentialProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_profile_keys(self) -> Self:
        for key, profile in self.profiles.items():
            if key != profile.name:
                raise ValueError("credential profile key does not match profile name")
        return self


class CredentialProfileNotFoundError(LookupError):
    pass


class DuplicateCredentialProfileError(ValueError):
    pass


class CredentialProfileInUseError(ValueError):
    pass


class CredentialProfileStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def initialize(self) -> None:
        if not self._path.exists():
            self.save(CredentialProfilesDocument())

    def load(self) -> CredentialProfilesDocument:
        return load_yaml_document(self._path, CredentialProfilesDocument)

    def save(self, document: CredentialProfilesDocument) -> None:
        save_yaml_document(self._path, document)

    def get(self, name: str) -> CredentialProfile:
        try:
            return self.load().profiles[name]
        except KeyError as error:
            raise CredentialProfileNotFoundError(f"Credential profile not found: {name}") from error

    def add(self, profile: CredentialProfile) -> CredentialProfilesDocument:
        document = self.load()
        if profile.name in document.profiles:
            raise DuplicateCredentialProfileError(
                f"Credential profile already exists: {profile.name}"
            )
        updated = CredentialProfilesDocument(profiles={**document.profiles, profile.name: profile})
        self.save(updated)
        return updated

    def remove(self, name: str) -> tuple[CredentialProfilesDocument, CredentialProfile]:
        document = self.load()
        profile = self.get(name)
        profiles = dict(document.profiles)
        del profiles[name]
        updated = CredentialProfilesDocument(profiles=profiles)
        self.save(updated)
        return updated, profile
