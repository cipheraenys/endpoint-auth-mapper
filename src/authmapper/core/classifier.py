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

#: Path prefixes that indicate deliberately public infrastructure endpoints.
#: Matching uses path-segment boundaries: ``/health`` matches ``/health`` and
#: ``/health/live`` but NOT ``/healthcare``.
_PUBLIC_HINTS = ("/health", "/healthz", "/ping", "/status", "/metrics", "/livez", "/readyz")


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
    """Decide whether a route is intentionally public.

    Matching uses exact or path-segment-descendant comparison to avoid
    false positives (e.g. ``/healthcare`` must NOT match ``/health``).
    """
    normalized = _normalize_route(route)
    for p in exempt_paths:
        if _is_segment_match(normalized, p):
            return True
    for hint in _PUBLIC_HINTS:
        if _is_segment_match(normalized, hint):
            return True
    return False


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
