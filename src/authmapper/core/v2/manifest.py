"""Strict rulepack manifest loading and engine compatibility checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .package import CapabilityMaturity, PackageLifecycle

MANIFEST_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_ID = "https://authmap.dev/schemas/rulepack-manifest-1.0.json"
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_RANGE_PART = re.compile(r"^(>=|>|<=|<|==)(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class ManifestError(ValueError):
    """Raised when a v2 package manifest is invalid or incompatible."""


@dataclass(frozen=True, slots=True)
class RulepackManifest:
    schema: str
    document_id: str
    id: str
    version: str
    engine: str
    languages: tuple[str, ...]
    runtimes: tuple[str, ...]
    framework: str | None
    lifecycle: PackageLifecycle
    capabilities: tuple[tuple[str, CapabilityMaturity], ...]
    applicability: tuple[tuple[str, str], ...]
    collision_group: str
    entrypoint: str


def load_manifest(path: Path, *, engine_version: str) -> RulepackManifest:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest '{path}': {exc}") from exc
    return parse_manifest(document, engine_version=engine_version)


def parse_manifest(document: Any, *, engine_version: str) -> RulepackManifest:
    validator = manifest_validator()
    try:
        validator.validate(document)
    except ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "<root>"
        raise ManifestError(f"invalid manifest at {location}: {exc.message}") from exc
    if not _version_satisfies(engine_version, document["engine"]):
        raise ManifestError(
            f"manifest requires engine {document['engine']!r}, running engine is {engine_version!r}"
        )
    return RulepackManifest(
        schema=document["$schema"],
        document_id=document["$id"],
        id=document["id"],
        version=document["version"],
        engine=document["engine"],
        languages=tuple(document["languages"]),
        runtimes=tuple(document["runtimes"]),
        framework=document.get("framework"),
        lifecycle=PackageLifecycle(document["lifecycle"]),
        capabilities=tuple(
            (name, CapabilityMaturity(value)) for name, value in sorted(document["capabilities"].items())
        ),
        applicability=tuple(sorted(document["applicability"].items())),
        collision_group=document["collision_group"],
        entrypoint=document["entrypoint"],
    )


def manifest_validator() -> Draft202012Validator:
    schema_path = files("authmapper.schemas").joinpath("rulepack-manifest-1.0.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ManifestError(f"bundled manifest schema is invalid: {exc.message}") from exc
    return Draft202012Validator(schema)


def _version_satisfies(version: str, constraint: str) -> bool:
    parsed = _parse_version(version)
    for part in constraint.split():
        match = _RANGE_PART.fullmatch(part)
        if match is None:
            return False
        operator = match.group(1)
        boundary = tuple(int(value) for value in match.groups()[1:])
        comparisons = {
            ">=": parsed >= boundary,
            ">": parsed > boundary,
            "<=": parsed <= boundary,
            "<": parsed < boundary,
            "==": parsed == boundary,
        }
        if not comparisons[operator]:
            return False
    return True


def _parse_version(version: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(version)
    if match is None:
        raise ManifestError(f"invalid engine version {version!r}")
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]
