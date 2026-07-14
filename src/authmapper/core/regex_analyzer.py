"""Regex-based analyzer."""
from __future__ import annotations

import re

from .analyzer import Analyzer
from .classifier import classify_state, looks_public, severity_for
from .model import AuthState, Confidence, Endpoint, Evidence, Finding
from .rulepack import ENDPOINT_MODEL_FILE, SCOPE_SAME_LINE, RulePack
from .safety import MatchProxy, SafeMatcher, redact
from .walker import SourceFile

_SUPPRESSION_RE = re.compile(r"authmap:ignore(?:\s+reason=(?P<reason>[^\n]+))?", re.IGNORECASE)

_FIX_HINTS = {
    AuthState.EXPOSED: "Requires authentication guard.",
    AuthState.UNKNOWN: "Review required. Auth guard may be missing or unrecognised.",
}

class RegexAnalyzer(Analyzer):
    def __init__(self, matcher: SafeMatcher, public_paths: tuple[str, ...] = ()) -> None:
        self._matcher = matcher
        self._public_paths = public_paths

    def analyze(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        return self._analyze(source, pack)

    def _analyze(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        """Produce findings for one file under one rule pack."""
        lines = source.text.splitlines()
        file_guard = self._find_file_scope_guard(source, pack)

        if pack.endpoint_model == ENDPOINT_MODEL_FILE:
            endpoints = [self._file_as_endpoint(source, pack)]
        else:
            endpoints = self._discover_routes(source, pack)

        findings: list[Finding] = []
        for endpoint, disc_conf in endpoints:
            findings.append(
                self._classify_endpoint(source, pack, endpoint, disc_conf, file_guard, lines)
            )
        return findings

    def _discover_routes(
        self, source: SourceFile, pack: RulePack
    ) -> list[tuple[Endpoint, Confidence]]:
        results: list[tuple[Endpoint, Confidence]] = []
        for ep_pattern in pack.endpoint_patterns:
            for match in self._matcher.finditer(ep_pattern.pattern, source.text):
                line_no = source.text.count("\n", 0, match.start()) + 1
                method = self._group(match, ep_pattern.method_group) or ep_pattern.default_method
                route = self._group(match, ep_pattern.path_group) or "*"
                endpoint = Endpoint(
                    file=source.relpath,
                    line=line_no,
                    method=method.upper(),
                    route=route,
                    language=pack.language,
                    framework=pack.framework,
                )
                # A matched, structured route gives us high discovery confidence.
                results.append((endpoint, Confidence.HIGH))
        return results

    def _file_as_endpoint(self, source: SourceFile, pack: RulePack) -> tuple[Endpoint, Confidence]:
        endpoint = Endpoint(
            file=source.relpath,
            line=1,
            method=pack.file_endpoint_method,
            route="/" + source.relpath,
            language=pack.language,
            framework=pack.framework,
        )
        # File-as-endpoint is a coarse model; treat discovery as MEDIUM so a
        # missing guard becomes UNKNOWN unless corroborated. (Classic PHP dirs of
        # api_*.php are the motivating case; we still avoid over-claiming.)
        return endpoint, Confidence.MEDIUM

    def _classify_endpoint(
        self,
        source: SourceFile,
        pack: RulePack,
        endpoint: Endpoint,
        discovery_confidence: Confidence,
        file_guard: Evidence | None,
        lines: list[str],
    ) -> Finding:
        same_line_guard = self._find_same_line_guard(endpoint, pack, lines)
        guard = same_line_guard
        relevant_evidence = same_line_guard or file_guard
        guard_found = guard is not None

        is_public = looks_public(endpoint.route, pack.exempt_paths + self._public_paths)

        # Confidence blends discovery confidence with guard evidence strength.
        confidence = self._effective_confidence(
            discovery_confidence,
            same_line_guard,
            file_guard,
            file_model=pack.endpoint_model == ENDPOINT_MODEL_FILE,
        )
        state = classify_state(guard_found=guard_found, confidence=confidence, is_public=is_public)
        severity = severity_for(state, confidence)

        evidence = tuple(e for e in (relevant_evidence,) if e is not None)
        finding = Finding(
            endpoint=endpoint,
            auth_state=state,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            rationale=self._rationale(state, relevant_evidence),
            fix_hint=_FIX_HINTS.get(state, ""),
        )
        return self._apply_suppression(finding, lines)

    # -- guard discovery -----------------------------------------------------

    def _find_file_scope_guard(self, source: SourceFile, pack: RulePack) -> Evidence | None:
        for signal in pack.auth_signals:
            if signal.scope != SCOPE_SAME_LINE:
                match = self._first(signal.pattern, source.text)
                if match is not None:
                    line_no = source.text.count("\n", 0, match.start()) + 1
                    return Evidence(
                        file=source.relpath,
                        line=line_no,
                        signal=signal.rule_id,
                        snippet=redact(match.group(0)),
                    )
        return None

    def _find_same_line_guard(
        self, endpoint: Endpoint, pack: RulePack, lines: list[str]
    ) -> Evidence | None:
        if not (1 <= endpoint.line <= len(lines)):
            return None
        line_text = lines[endpoint.line - 1]
        for signal in pack.auth_signals:
            if signal.scope != SCOPE_SAME_LINE:
                continue
            if self._first(signal.pattern, line_text) is not None:
                return Evidence(
                    file=endpoint.file,
                    line=endpoint.line,
                    signal=signal.rule_id,
                    snippet=redact(line_text),
                )
        return None

    def _effective_confidence(
        self,
        discovery_confidence: Confidence,
        same_line_guard: Evidence | None,
        file_guard: Evidence | None,
        *,
        file_model: bool,
    ) -> Confidence:
        # A same-line guard is strong corroboration; a file guard on a
        # coarsely-discovered endpoint stays capped at the discovery level.
        if same_line_guard is not None:
            return Confidence.HIGH
        if file_guard is not None:
            return discovery_confidence if file_model else Confidence.MEDIUM
        return discovery_confidence

    # -- suppression ---------------------------------------------------------

    def _apply_suppression(self, finding: Finding, lines: list[str]) -> Finding:
        idx = finding.endpoint.line - 1
        window = lines[max(0, idx - 1): idx + 1]  # endpoint line and the line above
        for text in window:
            m = _SUPPRESSION_RE.search(text)
            if m:
                reason = (m.group("reason") or "unspecified").strip()
                return finding.with_suppression(reason)
        return finding

    # -- small helpers -------------------------------------------------------

    def _first(self, pattern: re.Pattern[str], text: str) -> MatchProxy | re.Match[str] | None:
        matches = self._matcher.finditer(pattern, text)
        return matches[0] if matches else None

    @staticmethod
    def _group(match: MatchProxy | re.Match[str], group: int | None) -> str | None:
        if group is None:
            return None
        try:
            return match.group(group)
        except (IndexError, re.error):  # pragma: no cover - defensive
            return None

    @staticmethod
    def _rationale(state: AuthState, guard: Evidence | None) -> str:
        if state is AuthState.PROTECTED and guard is not None:
            return f"Auth guard '{guard.signal}' detected."
        if state is AuthState.EXPOSED:
            return "No authentication guard detected for a confidently identified endpoint."
        if state is AuthState.UNKNOWN:
            if guard is not None:
                return "An authentication signal exists but cannot be associated with this endpoint."
            return "Endpoint structure or guard could not be confidently resolved."
        if state is AuthState.PUBLIC:
            return "Route matches an explicit public-path declaration."
        return ""
