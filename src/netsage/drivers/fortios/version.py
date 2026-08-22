"""Typed FortiOS firmware versions and safe range matching."""

from __future__ import annotations

import re
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

_VERSION = re.compile(r"(?i)^v?(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+|x))?$")


class FortiOSVersion(BaseModel):
    """A parsed firmware identity; unknown patch levels never compare as concrete."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    major: int = Field(ge=0, le=99)
    minor: int = Field(ge=0, le=99)
    patch: int | None = Field(default=None, ge=0, le=999)
    build: int | None = Field(default=None, ge=0)
    branch_point: int | None = Field(default=None, ge=0)
    release: str | None = Field(default=None, max_length=80)

    @classmethod
    def parse(
        cls,
        value: str,
        *,
        build: int | None = None,
        branch_point: int | None = None,
        release: str | None = None,
    ) -> Self:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            raise ValueError("FortiOS version is invalid")
        patch_text = match.group("patch")
        return cls(
            major=int(match.group("major")),
            minor=int(match.group("minor")),
            patch=(int(patch_text) if patch_text and patch_text.casefold() != "x" else None),
            build=build,
            branch_point=branch_point,
            release=release,
        )

    @property
    def display(self) -> str:
        patch = str(self.patch) if self.patch is not None else "x"
        return f"{self.major}.{self.minor}.{patch}"

    @property
    def concrete(self) -> bool:
        return self.patch is not None

    def core_tuple(self) -> tuple[int, int, int] | None:
        if self.patch is None:
            return None
        return self.major, self.minor, self.patch

    def matches(
        self,
        *,
        minimum: FortiOSVersion | None = None,
        maximum: FortiOSVersion | None = None,
    ) -> bool:
        current = self.core_tuple()
        if current is None and (minimum is not None or maximum is not None):
            return False
        if current is None:
            return True
        if minimum is not None:
            minimum_value = minimum.core_tuple()
            if minimum_value is None or current < minimum_value:
                return False
        if maximum is not None:
            maximum_value = maximum.core_tuple()
            if maximum_value is None or current > maximum_value:
                return False
        return True
