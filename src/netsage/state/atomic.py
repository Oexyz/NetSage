"""Versioned YAML loading and atomic, restrictive local-state writes."""

import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

import yaml
from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

SCHEMA_VERSION = 1
_JSON_MAPPING = TypeAdapter(dict[str, JsonValue])


class StateError(RuntimeError):
    """Base error which never embeds state-file content."""


class StateFileInvalidError(StateError):
    pass


class StateSchemaVersionError(StateError):
    pass


class StateWriteError(StateError):
    pass


def _ensure_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def atomic_write_yaml(path: Path, data: Mapping[str, JsonValue]) -> None:
    """Write YAML via a same-directory temporary file and atomic replace."""

    content = yaml.safe_dump(dict(data), sort_keys=True, allow_unicode=True)
    descriptor = -1
    temporary_path: Path | None = None
    try:
        _ensure_directory(path.parent)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            text=True,
        )
        temporary_path = Path(temporary_name)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        if os.name != "nt":
            try:
                directory_descriptor = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            except OSError:
                pass
    except OSError as error:
        raise StateWriteError(f"Unable to write NetSage state file: {path.name}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def load_yaml_document[DocumentT: BaseModel](path: Path, model: type[DocumentT]) -> DocumentT:
    if not path.exists():
        raise StateFileInvalidError(f"NetSage state file is missing: {path.name}")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise StateFileInvalidError(f"NetSage state file is invalid: {path.name}") from error
    if not isinstance(loaded, dict):
        raise StateFileInvalidError(f"NetSage state file is invalid: {path.name}")
    version = loaded.get("schema_version")
    if version != SCHEMA_VERSION:
        raise StateSchemaVersionError(
            f"Unsupported NetSage state schema in {path.name}: {version!r}"
        )
    try:
        return model.model_validate(loaded)
    except ValidationError as error:
        raise StateFileInvalidError(f"NetSage state file is invalid: {path.name}") from error


def save_yaml_document(path: Path, document: BaseModel) -> None:
    data = _JSON_MAPPING.validate_python(document.model_dump(mode="json"))
    atomic_write_yaml(path, data)
