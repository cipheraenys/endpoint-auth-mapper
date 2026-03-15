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


def fingerprint(finding: Finding) -> str:
    """Return a stable identifier for a finding, insensitive to line moves."""
    ep = finding.endpoint
    material = f"{finding.auth_state}|{ep.route}|{ep.method}|{ep.file}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    """Load a set of accepted fingerprints from ``path`` (empty if absent)."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return set(data.get("fingerprints", []))


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
