"""Typed runtime models for the generated FortiOS CLI knowledge catalog."""

from enum import StrEnum
from re import compile as compile_pattern
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsage.models import Capability
from netsage.policies import OperationClass

_ID_PATTERN = compile_pattern(r"^[a-z0-9][a-z0-9_.:-]{0,767}$")


class FortiOSArgumentKind(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ENUM = "enum"
    IP_ADDRESS = "ip_address"
    IPV4_ADDRESS = "ipv4_address"
    IPV6_ADDRESS = "ipv6_address"
    NETWORK = "network"
    HOSTNAME = "hostname"
    INTERFACE = "interface"
    VDOM = "vdom"
    POLICY_ID = "policy_id"
    PORT = "port"
    PROTOCOL = "protocol"


class FortiOSCommandContext(StrEnum):
    UNSPECIFIED = "unspecified"
    CONFIGURATION = "configuration"
    GLOBAL = "global"
    VDOM = "vdom"
    GLOBAL_OR_VDOM = "global_or_vdom"


class FortiOSExecutionSupport(StrEnum):
    CATALOG_ONLY = "catalog_only"
    STRUCTURED = "structured"


class FortiOSParserSupport(StrEnum):
    NONE = "none"
    SANITIZED_TEXT = "sanitized_text"
    TYPED = "typed"


class FortiOSSourceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    document: str = "fortios.md"
    line: int = Field(ge=1)
    page: int | None = Field(default=None, ge=1)
    section: str


class FortiOSArgumentDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    placeholder: str = Field(min_length=2, max_length=300)
    kind: FortiOSArgumentKind
    required: bool = True
    choices: tuple[str, ...] = ()
    sensitive: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _ID_PATTERN.fullmatch(value):
            raise ValueError("FortiOS argument name is invalid")
        return value

    @model_validator(mode="after")
    def validate_choices(self) -> Self:
        if self.kind in {FortiOSArgumentKind.ENUM, FortiOSArgumentKind.BOOLEAN}:
            if len(self.choices) < 2:
                raise ValueError("enum and boolean arguments require choices")
        elif self.choices:
            raise ValueError("only enum and boolean arguments can declare choices")
        return self


class FortiOSCommandDefinition(BaseModel):
    """One known source-derived syntax; knowledge does not imply execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=768)
    path: str = Field(min_length=1, max_length=1600)
    syntax: str = Field(min_length=1, max_length=5000)
    scope: str | None = Field(default=None, max_length=3000)
    description: str | None = Field(default=None, max_length=2000)
    command_class: OperationClass
    capability: Capability | None = None
    context: FortiOSCommandContext
    arguments: tuple[FortiOSArgumentDefinition, ...] = ()
    renderable: bool = False
    observe_allowed: bool
    execution_support: FortiOSExecutionSupport = FortiOSExecutionSupport.CATALOG_ONLY
    parser_support: FortiOSParserSupport = FortiOSParserSupport.NONE
    source: FortiOSSourceReference

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _ID_PATTERN.fullmatch(value):
            raise ValueError("FortiOS command ID is invalid")
        return value

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        if self.execution_support is FortiOSExecutionSupport.STRUCTURED and not self.renderable:
            raise ValueError("structured execution requires safe rendering")
        if self.parser_support is not FortiOSParserSupport.NONE:
            if self.execution_support is not FortiOSExecutionSupport.STRUCTURED:
                raise ValueError("output support requires structured execution")
        if self.observe_allowed != (self.command_class is OperationClass.READ_ONLY):
            raise ValueError("Observe allowance must match read-only classification")
        return self

    @property
    def executable_in_observe(self) -> bool:
        return self.observe_allowed and self.execution_support is FortiOSExecutionSupport.STRUCTURED


class FortiOSCatalogCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_topic_commands: int = Field(ge=0)
    source_syntax_commands: int = Field(ge=0)
    source_context_commands: int = Field(ge=0)
    source_non_command_artifacts: int = Field(ge=0)
    commands_discovered: int = Field(ge=0)
    commands_catalogued: int = Field(ge=0)
    source_definitions_uncatalogued: int = Field(ge=0)
    read_only: int = Field(ge=0)
    diagnostic: int = Field(ge=0)
    configuration: int = Field(ge=0)
    destructive: int = Field(ge=0)
    structured_executable: int = Field(ge=0)
    executable_in_observe: int = Field(ge=0)
    typed_parsers: int = Field(ge=0)
    sanitized_text_parsers: int = Field(ge=0)
    catalog_only: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_totals(self) -> Self:
        if self.commands_discovered != self.commands_catalogued:
            raise ValueError("FortiOS catalog coverage is incomplete")
        if self.source_definitions_uncatalogued != 0:
            raise ValueError("FortiOS source definitions remain uncatalogued")
        source_total = (
            self.source_topic_commands + self.source_syntax_commands + self.source_context_commands
        )
        if self.commands_discovered != source_total:
            raise ValueError("FortiOS source command totals are inconsistent")
        classes = self.read_only + self.diagnostic + self.configuration + self.destructive
        if classes != self.commands_catalogued:
            raise ValueError("FortiOS command-class totals are inconsistent")
        if self.structured_executable + self.catalog_only != self.commands_catalogued:
            raise ValueError("FortiOS execution-support totals are inconsistent")
        return self


class FortiOSCommandManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    generated_notice: str
    source_document: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_bytes: int = Field(gt=0)
    source_lines: int = Field(gt=0)
    fortios_version: str
    coverage: FortiOSCatalogCoverage
    definitions: tuple[FortiOSCommandDefinition, ...]

    @model_validator(mode="after")
    def validate_definitions(self) -> Self:
        ids = [definition.id for definition in self.definitions]
        if len(ids) != len(set(ids)):
            raise ValueError("FortiOS command IDs must be unique")
        if len(ids) != self.coverage.commands_catalogued:
            raise ValueError("FortiOS manifest definition total is inconsistent")
        return self
