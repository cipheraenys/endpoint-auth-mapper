"""M2-B JSON Schema 2020-12 manifest conformance tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmapper.core.v2 import CapabilityMaturity, ManifestError, PackageLifecycle, load_manifest, parse_manifest
from authmapper.core.v2.manifest import MANIFEST_SCHEMA_ID, manifest_validator


def test_valid_manifest_parses_to_typed_contract(fixtures_dir: Path):
    manifest = load_manifest(fixtures_dir / "v2_manifests" / "valid.json", engine_version="0.1.2")

    assert manifest.schema == MANIFEST_SCHEMA_ID
    assert manifest.lifecycle is PackageLifecycle.ACTIVE
    assert dict(manifest.capabilities)["endpoint_discovery"] is CapabilityMaturity.VERIFIED
    assert manifest.languages == ("javascript", "typescript")


@pytest.mark.parametrize(
    "name",
    [
        "invalid-unknown-field.json",
        "invalid-lifecycle.json",
        "invalid-capability.json",
        "invalid-version.json",
    ],
)
def test_invalid_manifest_fixtures_are_rejected(fixtures_dir: Path, name: str):
    with pytest.raises(ManifestError, match="invalid manifest"):
        load_manifest(fixtures_dir / "v2_manifests" / name, engine_version="0.1.2")


def test_incompatible_engine_is_rejected(fixtures_dir: Path):
    with pytest.raises(ManifestError, match="requires engine"):
        load_manifest(fixtures_dir / "v2_manifests" / "valid.json", engine_version="0.2.0")


def test_validator_exercises_ref_composition_and_unevaluated_properties(fixtures_dir: Path):
    validator = manifest_validator()
    schema = validator.schema
    valid = json.loads((fixtures_dir / "v2_manifests" / "valid.json").read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == MANIFEST_SCHEMA_ID
    assert schema["$ref"] == "#/$defs/manifest"
    assert schema["$defs"]["manifest"]["unevaluatedProperties"] is False
    assert schema["$defs"]["capabilities"]["unevaluatedProperties"] is False
    assert not list(validator.iter_errors(valid))

    valid["capabilities"]["severity"] = "high"
    errors = list(validator.iter_errors(valid))
    assert any("Unevaluated properties are not allowed" in error.message for error in errors)

    valid["capabilities"].pop("severity")
    valid["applicability"] = {}
    assert not list(validator.iter_errors(valid))


def test_manifest_schema_const_is_enforced(fixtures_dir: Path):
    document = json.loads((fixtures_dir / "v2_manifests" / "valid.json").read_text(encoding="utf-8"))
    document["$schema"] = "https://example.invalid/schema.json"

    with pytest.raises(ManifestError, match=r"\$schema"):
        parse_manifest(document, engine_version="0.1.2")
