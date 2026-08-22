"""Atomic safe-by-default JSON export for compatibility reports."""

import os
import tempfile
from pathlib import Path

from netsage.compatibility.models import FortiOSCompatibilityReport


class CompatibilityExportError(RuntimeError):
    pass


def export_compatibility_report(
    report: FortiOSCompatibilityReport,
    path: Path,
    *,
    force: bool = False,
) -> Path:
    target = path.resolve()
    if target.suffix.casefold() != ".json":
        raise CompatibilityExportError("Compatibility export must use a .json file")
    if target.exists() and target.is_symlink():
        raise CompatibilityExportError("Compatibility export refuses symbolic links")
    if target.exists() and not force:
        raise CompatibilityExportError("Compatibility export file already exists")
    if target.exists() and not target.is_file():
        raise CompatibilityExportError("Compatibility export target is not a file")
    content = report.anonymized_copy().model_dump_json(indent=2) + "\n"
    descriptor = -1
    temporary: Path | None = None
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            text=True,
        )
        temporary = Path(name)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
        if os.name != "nt":
            target.chmod(0o600)
        return target
    except OSError as error:
        raise CompatibilityExportError("Unable to write compatibility export") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
