"""Auth-state and severity decision logic.

This module is pure: given an endpoint, whether a guard was found, and how
confident discovery was, it returns the ``AuthState`` and ``Severity``. Isolating
this makes the fail-safe policy explicit, testable, and easy to audit.

The single most important rule lives here:

    An endpoint is only ever EXPOSED when discovery confidence is HIGH.
    Anything less collapses to UNKNOWN — silence is never treated as safety.
"""

from __future__ import annotations

from .model import AuthState, Confidence, Severity


def _normalize_route(route: str) -> str:
    """Lowercase, strip query string and trailing slash for comparison."""
    normalized = route.lower().split("?")[0].rstrip("/")
    return normalized or "/"


def _is_segment_match(route: str, prefix: str) -> bool:
    """True when ``route`` equals ``prefix`` or is a path-segment descendant.

    ``/health`` matches ``/health`` and ``/health/live``, but NOT ``/healthcare``.
    """
    p = prefix.lower().rstrip("/") or "/"
    return route == p or route.startswith(p + "/")


def looks_public(route: str, exempt_paths: tuple[str, ...]) -> bool:
    """Return whether a route matches an explicit rule-pack declaration.

    Route names are never public hints. Exact segment comparison avoids
    false positives (e.g. ``/healthcare`` must NOT match ``/health``).
    """
    normalized = _normalize_route(route)
    return any(_is_segment_match(normalized, path) for path in exempt_paths)


def classify_state(
    *,
    guard_found: bool,
    confidence: Confidence,
    is_public: bool,
) -> AuthState:
    """Resolve the authentication posture (the fail-safe core)."""
    if is_public:
        return AuthState.PUBLIC
    if guard_found:
        return AuthState.PROTECTED
    # No guard found. Only call it EXPOSED when we are highly confident we even
    # understood the endpoint; otherwise defer to human review as UNKNOWN.
    if confidence is Confidence.HIGH:
        return AuthState.EXPOSED
    return AuthState.UNKNOWN


def severity_for(state: AuthState, confidence: Confidence) -> Severity:
    """Map an auth state (and confidence) to a reportable severity."""
    if state is AuthState.EXPOSED:
        return Severity.CRITICAL if confidence is Confidence.HIGH else Severity.HIGH
    if state is AuthState.UNKNOWN:
        return Severity.MEDIUM
    if state is AuthState.PROTECTED:
        return Severity.INFO
    # PUBLIC
    return Severity.INFO
