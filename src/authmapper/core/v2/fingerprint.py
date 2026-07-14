"""Algorithm-versioned semantic fingerprints for v2 report identity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .contracts import ENDPOINT_FINGERPRINT_ALGORITHM, PROOF_FINGERPRINT_ALGORITHM
from .model import Fact, Proof


@dataclass(frozen=True, slots=True)
class Fingerprint:
    algorithm: str
    components: tuple[tuple[str, str], ...]
    value: str


def endpoint_fingerprint(endpoint: Fact) -> Fingerprint:
    components = (
        ("kind", endpoint.kind.value),
        ("method", endpoint.method or ""),
        ("path", endpoint.path or ""),
    )
    return _fingerprint(ENDPOINT_FINGERPRINT_ALGORITHM, components)


def proof_fingerprint(endpoint: Fact, proof: Proof) -> Fingerprint:
    components = (
        ("endpoint", endpoint_fingerprint(endpoint).value),
        ("kind", proof.kind.value),
        ("facts", "\x1f".join(proof.fact_ids)),
        ("associations", "\x1f".join(proof.association_ids)),
        ("relations", "\x1f".join(proof.relation_ids)),
    )
    return _fingerprint(PROOF_FINGERPRINT_ALGORITHM, components)


def _fingerprint(algorithm: str, components: tuple[tuple[str, str], ...]) -> Fingerprint:
    material = json.dumps(
        {"algorithm": algorithm, "components": dict(components)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return Fingerprint(algorithm, components, hashlib.sha256(material.encode("utf-8")).hexdigest())
