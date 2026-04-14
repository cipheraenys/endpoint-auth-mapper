"""Unit tests for the fail-safe classification policy."""

from __future__ import annotations

from authmapper.core.classifier import classify_state, looks_public, severity_for
from authmapper.core.model import AuthState, Confidence, Severity


def test_guard_found_is_protected():
    state = classify_state(guard_found=True, confidence=Confidence.HIGH, is_public=False)
    assert state is AuthState.PROTECTED


def test_no_guard_high_confidence_is_exposed():
    state = classify_state(guard_found=False, confidence=Confidence.HIGH, is_public=False)
    assert state is AuthState.EXPOSED


def test_no_guard_low_confidence_is_unknown_not_exposed():
    # The core fail-safe invariant: uncertainty is never silently "safe" nor
    # over-claimed as EXPOSED.
    for conf in (Confidence.LOW, Confidence.MEDIUM):
        state = classify_state(guard_found=False, confidence=conf, is_public=False)
        assert state is AuthState.UNKNOWN


def test_public_short_circuits():
    state = classify_state(guard_found=False, confidence=Confidence.HIGH, is_public=True)
    assert state is AuthState.PUBLIC


def test_looks_public_matches_health_and_exempt():
    assert looks_public("/health", ())
    assert looks_public("/status/live", ())
    assert looks_public("/custom", ("/custom",))
    assert not looks_public("/api/admin", ())


def test_severity_mapping():
    assert severity_for(AuthState.EXPOSED, Confidence.HIGH) is Severity.CRITICAL
    assert severity_for(AuthState.EXPOSED, Confidence.MEDIUM) is Severity.HIGH
    assert severity_for(AuthState.UNKNOWN, Confidence.MEDIUM) is Severity.MEDIUM
    assert severity_for(AuthState.PROTECTED, Confidence.HIGH) is Severity.INFO
