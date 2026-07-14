"""Baseline support for incremental adoption.

Legacy codebases (the common CVP case) often start with many findings. A
baseline records the *fingerprints* of already-known findings so CI can fail
only on *new* ones. This lets teams adopt the gate immediately and burn down
debt over time without a red pipeline on day one.

A fingerprint is intentionally coarse (state + endpoint identity, not line
number) so cosmetic edits do not churn the baseline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from ..core.model import Finding


class BaselineError(Exception):
    """Raised when a baseline file is present but invalid.

    An explicitly configured baseline must exist and match the baseline schema.
    """


def fingerprint(finding: Finding) -> str:
    """Return a stable identifier for a finding, insensitive to line moves."""
    ep = finding.endpoint
    material = f"{finding.auth_state}|{ep.route}|{ep.method}|{ep.file}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    """Load a set of accepted fingerprints from ``path``.

    Raises :class:`BaselineError` when the file does not exist, cannot be read,
    contains invalid JSON, or has an unexpected structure.  Silently ignoring
    a corrupt baseline would pass every finding ungated, which is the opposite
    of the intent.
    """
    if not path.exists():
        raise BaselineError(f"baseline does not exist: '{path}'")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"invalid baseline '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise BaselineError(
            f"invalid baseline '{path}': expected a JSON object, "
            f"got {type(data).__name__}"
        )
    unknown = sorted(set(data) - {"version", "fingerprints"})
    if unknown:
        raise BaselineError(
            f"invalid baseline '{path}': unknown field(s): {', '.join(unknown)}"
        )
    if data.get("version") != "1.0":
        raise BaselineError(f"invalid baseline '{path}': 'version' must be '1.0'")
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, list) or any(
        not isinstance(item, str) or not item for item in fingerprints
    ):
        raise BaselineError(
            f"invalid baseline '{path}': 'fingerprints' must be a list of non-empty strings"
        )
    return set(fingerprints)


def build_baseline(findings: Iterable[Finding]) -> str:
    """Serialize the fingerprints of ``findings`` into a baseline document."""
    prints = sorted({fingerprint(f) for f in findings})
    return json.dumps(
        {"version": "1.0", "fingerprints": prints},
        indent=2,
        sort_keys=True,
    )


def is_baselined(finding: Finding, accepted: set[str]) -> bool:
    """Return True when ``finding`` is present in the accepted baseline set."""
    return fingerprint(finding) in accepted
