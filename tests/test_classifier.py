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


def test_looks_public_requires_explicit_declaration():
    assert not looks_public("/health", ())
    assert not looks_public("/status/live", ())
    assert looks_public("/custom", ("/custom",))
    assert not looks_public("/api/admin", ())


def test_severity_mapping():
    assert severity_for(AuthState.EXPOSED, Confidence.HIGH) is Severity.CRITICAL
    assert severity_for(AuthState.EXPOSED, Confidence.MEDIUM) is Severity.HIGH
    assert severity_for(AuthState.UNKNOWN, Confidence.MEDIUM) is Severity.MEDIUM
    assert severity_for(AuthState.PROTECTED, Confidence.HIGH) is Severity.INFO


# -- segment-boundary matching hardening ------------------------------------


def test_looks_public_rejects_prefix_overlap():
    """'/healthcare' must NOT match '/health' — segment boundaries required."""
    assert not looks_public("/healthcare", ())
    assert not looks_public("/statuspages", ())
    assert not looks_public("/pingdom-webhook", ())


def test_looks_public_accepts_nested():
    """/health/live is a descendant of /health and should match."""
    assert looks_public("/health/live", ("/health",))
    assert looks_public("/status/ready", ("/status",))
    assert looks_public("/metrics/prometheus", ("/metrics",))


def test_looks_public_normalizes_trailing_slash():
    assert looks_public("/health/", ("/health",))
    assert looks_public("/status/", ("/status",))


def test_looks_public_normalizes_query_string():
    assert looks_public("/health?v=1", ("/health",))
    assert looks_public("/ping?timeout=5", ("/ping",))


def test_looks_public_exempt_segment_boundary():
    """Custom exempt paths also use segment-boundary matching."""
    assert looks_public("/api/public", ("/api/public",))
    assert looks_public("/api/public/docs", ("/api/public",))
    assert not looks_public("/api/publication", ("/api/public",))


def test_looks_public_root_exempt():
    """Root path works correctly."""
    assert looks_public("/", ("/",))
