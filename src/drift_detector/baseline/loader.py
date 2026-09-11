"""Schema validation and accidental-corruption detection (not authenticity)."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from drift_detector.baseline.normalizers import stable
from drift_detector.models import Baseline, DetectorError


def digest(document: dict) -> str:
    return hashlib.sha256(stable(document).encode()).hexdigest()


def load_baseline(path: str | Path) -> Baseline:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        checksum = raw.pop("integrity_sha256")
        if checksum != digest(raw):
            raise DetectorError(
                "Baseline integrity check failed. Recover the trusted copy; do not rebaseline unexplained drift."
            )
        return Baseline.model_validate(raw)
    except DetectorError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ValidationError) as exc:
        raise DetectorError(
            f"Cannot load baseline {path}. Generate it after Terraform apply, or recover a valid schema-v1 copy."
        ) from exc


def save_baseline(baseline: Baseline, path: str | Path, force: bool = False) -> None:
    destination = Path(path)
    if destination.exists() and not force:
        raise DetectorError(
            "Baseline already exists. Review intended changes and use --force to replace it."
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline.model_dump()
    payload["integrity_sha256"] = digest(payload)
    # Private temp file + atomic rename. An unforced creation uses a hard link to avoid overwrite races.
    fd, temp = tempfile.mkstemp(prefix=".baseline-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        if force:
            os.replace(temp, destination)
        else:
            try:
                os.link(temp, destination)
            except FileExistsError as exc:
                raise DetectorError(
                    "Baseline already exists. Use --force only after review."
                ) from exc
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
