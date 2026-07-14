"""Bounded extractor for M1's synthetic Express evidence corpus.

This module records source facts and relationships only. It never resolves auth
semantics or produces endpoint verdicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceSpan:
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True)
class Observation:
    id: str
    kind: str
    span: SourceSpan
    attributes: tuple[tuple[str, str], ...] = ()

    def attribute(self, name: str) -> str | None:
        return dict(self.attributes).get(name)


@dataclass(frozen=True)
class ScopeNode:
    id: str
    kind: str
    span: SourceSpan
    parent_id: str | None = None


@dataclass(frozen=True)
class CompositionEdge:
    id: str
    kind: str
    from_id: str
    to_id: str
    span: SourceSpan
    attributes: tuple[tuple[str, str], ...] = ()

    def attribute(self, name: str) -> str | None:
        return dict(self.attributes).get(name)


@dataclass(frozen=True)
class AssociationEdge:
    id: str
    endpoint_id: str
    evidence_id: str
    scope_id: str
    reason: str
    span: SourceSpan | None = None


@dataclass(frozen=True)
class UnresolvedObservation:
    id: str
    subject_id: str | None
    reason: str
    span: SourceSpan


@dataclass(frozen=True)
class SpikeArtifact:
    observations: tuple[Observation, ...]
    scopes: tuple[ScopeNode, ...]
    composition_edges: tuple[CompositionEdge, ...]
    associations: tuple[AssociationEdge, ...]
    unresolved: tuple[UnresolvedObservation, ...]


_ROUTER = re.compile(r"^\s*const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*express\.Router\s*\(\s*\)\s*;")
_APPLICATION = re.compile(r"^\s*const\s+app\s*=\s*express\s*\(\s*\)\s*;")
_ROUTE = re.compile(
    r"^\s*(?P<receiver>[A-Za-z_$][\w$]*)\.(?P<method>get|post|put|delete|patch|head|options|all)\s*"
    r"\(\s*(?P<quote>['\"`])(?P<path>[^'\"`]+)(?P=quote)(?P<tail>.*)\)\s*;?\s*$",
    re.IGNORECASE,
)
_MOUNT = re.compile(
    r"^\s*(?P<receiver>[A-Za-z_$][\w$]*)\.use\s*\(\s*(?P<quote>['\"`])(?P<path>[^'\"`]+)"
    r"(?P=quote)\s*,\s*(?P<child>[A-Za-z_$][\w$]*)\s*\)\s*;?\s*$"
)
_MIDDLEWARE = re.compile(r"^\s*(?P<receiver>[A-Za-z_$][\w$]*)\.use\s*\(\s*(?P<name>[A-Za-z_$][\w$]*)\s*\)\s*;?\s*$")
_PUBLIC = re.compile(r"^\s*authmap\.public\s*\(\s*(?P<quote>['\"`])(?P<path>[^'\"`]+)(?P=quote)\s*\)\s*;?\s*$")
_DYNAMIC = re.compile(r"^\s*(?P<receiver>[A-Za-z_$][\w$]*)\.(?:use|get|post|put|delete|patch|head|options|all)\s*\(")


def extract_express_spike(path: Path, *, root: Path | None = None) -> SpikeArtifact:
    """Extract literal M1 forms from a synthetic JavaScript fixture.

    Statements must be single-line and unaliased. Anything registration-shaped
    that fails a supported literal form becomes an explicit unresolved fact.
    """
    relative = path.relative_to(root).as_posix() if root is not None else path.name
    lines = path.read_text(encoding="utf-8").splitlines()
    observations: list[Observation] = []
    scopes: list[ScopeNode] = []
    composition_edges: list[CompositionEdge] = []
    associations: list[AssociationEdge] = []
    unresolved: list[UnresolvedObservation] = []
    receiver_scopes: dict[str, str] = {"app": "scope:application:app"}
    ambiguous_receivers: set[str] = set()
    app_span = _span(relative, 1, 1, 1, 1)
    scopes.append(ScopeNode("scope:application:app", "application", app_span))
    mounts: dict[str, tuple[str, str, SourceSpan]] = {}
    middleware: dict[str, list[tuple[str, int, SourceSpan]]] = {}
    sequence = 0

    for line_number, line in enumerate(lines, start=1):
        code = line.split("//", 1)[0].rstrip()
        if not code:
            continue
        application_match = _APPLICATION.match(code)
        if application_match:
            scopes[0] = ScopeNode(
                "scope:application:app",
                "application",
                _match_span(relative, line_number, application_match),
            )
            continue
        router_match = _ROUTER.match(code)
        if router_match:
            name = router_match["name"]
            span = _span(
                relative,
                line_number,
                router_match.start("name") + 1,
                line_number,
                router_match.end("name") + 1,
            )
            if name in receiver_scopes:
                ambiguous_receivers.add(name)
                unresolved.append(_unresolved(span, None, "duplicate router receiver declaration"))
                continue
            scope_id = f"scope:router:{name}"
            receiver_scopes[name] = scope_id
            scopes.append(ScopeNode(scope_id, "router", span))
            observations.append(_observation("router", name, span, name=name))
            continue
        public_match = _PUBLIC.match(code)
        if public_match:
            span = _match_span(relative, line_number, public_match)
            observations.append(
                _observation("public_override", f"public:{line_number}", span, path=public_match["path"])
            )
            continue
        mount_match = _MOUNT.match(code)
        if mount_match:
            sequence += 1
            receiver = mount_match["receiver"]
            child = mount_match["child"]
            span = _match_span(relative, line_number, mount_match)
            if receiver in ambiguous_receivers or child in ambiguous_receivers:
                unresolved.append(_unresolved(span, None, "mount receiver or child has a duplicate declaration"))
                continue
            if receiver not in receiver_scopes or child not in receiver_scopes:
                unresolved.append(
                    _unresolved(span, None, "mount receiver or child is not a known literal router")
                )
                continue
            mount_id = f"mount:{line_number}"
            observations.append(_observation("mount", mount_id, span, path=mount_match["path"], order=str(sequence)))
            composition_edges.append(
                CompositionEdge(
                    f"edge:mount:{line_number}",
                    "mount",
                    receiver_scopes[receiver],
                    receiver_scopes[child],
                    span,
                    (("path", mount_match["path"]), ("order", str(sequence))),
                )
            )
            mounts[child] = (receiver, mount_match["path"], span)
            continue
        middleware_match = _MIDDLEWARE.match(code)
        if middleware_match:
            sequence += 1
            receiver = middleware_match["receiver"]
            span = _match_span(relative, line_number, middleware_match)
            if receiver in ambiguous_receivers:
                unresolved.append(_unresolved(span, None, "middleware receiver has a duplicate declaration"))
                continue
            if receiver not in receiver_scopes:
                unresolved.append(
                    _unresolved(span, None, "middleware receiver is not a known literal router")
                )
                continue
            observation = _observation(
                "middleware", f"middleware:{line_number}", span, name=middleware_match["name"], order=str(sequence)
            )
            observations.append(observation)
            middleware.setdefault(receiver, []).append((observation.id, sequence, span))
            continue
        route_match = _ROUTE.match(code)
        if route_match:
            sequence += 1
            receiver = route_match["receiver"]
            span = _match_span(relative, line_number, route_match)
            if receiver in ambiguous_receivers:
                unresolved.append(_unresolved(span, None, "route receiver has a duplicate declaration"))
                continue
            if receiver not in receiver_scopes:
                unresolved.append(
                    _unresolved(span, None, "route receiver is not a known literal router")
                )
                continue
            endpoint = _observation(
                "endpoint",
                f"endpoint:{line_number}",
                span,
                method=route_match["method"].upper(),
                path=_normalized_path(receiver, route_match["path"], mounts),
                order=str(sequence),
            )
            observations.append(endpoint)
            route_scope_id = f"scope:route:{line_number}"
            scopes.append(ScopeNode(route_scope_id, "route", span, receiver_scopes[receiver]))
            composition_edges.append(
                CompositionEdge(
                    f"edge:scope:{line_number}",
                    "contains",
                    receiver_scopes[receiver],
                    route_scope_id,
                    span,
                    (("order", str(sequence)),),
                )
            )
            handler = _handler_reference(route_match["tail"])
            if handler is not None:
                handler_column = route_match.start("tail") + route_match["tail"].rfind(handler) + 1
                handler_span = _span(
                    relative,
                    line_number,
                    handler_column,
                    line_number,
                    handler_column + len(handler),
                )
                handler_id = f"handler:{line_number}"
                observations.append(_observation("handler_reference", handler_id, handler_span, name=handler))
                handler_scope_id = f"scope:handler:{line_number}"
                scopes.append(ScopeNode(handler_scope_id, "handler", handler_span, route_scope_id))
                composition_edges.append(
                    CompositionEdge(
                        f"edge:handler:{line_number}",
                        "handler_reference",
                        route_scope_id,
                        handler_scope_id,
                        handler_span,
                    )
                )
            for evidence_id, _middleware_order, middleware_span in middleware.get(receiver, []):
                associations.append(
                    AssociationEdge(
                        f"association:{line_number}:{evidence_id}",
                        endpoint.id,
                        evidence_id,
                        receiver_scopes[receiver],
                        f"router middleware registered before route ({_middleware_order} < {sequence})",
                        middleware_span,
                    )
                )
            for name in _inline_middleware(route_match["tail"]):
                evidence = _observation(
                    "middleware", f"inline:{line_number}:{name}", span, name=name, order=str(sequence)
                )
                observations.append(evidence)
                associations.append(
                    AssociationEdge(
                        f"association:{line_number}:{evidence.id}",
                        endpoint.id,
                        evidence.id,
                        route_scope_id,
                        f"inline route middleware at registration order {sequence}",
                        span,
                    )
                )
            continue
        if _DYNAMIC.match(code):
            span = _span(relative, line_number, 1, line_number, len(code) + 1)
            dynamic_id = f"dynamic_route:{line_number}"
            observations.append(_observation("dynamic_route", dynamic_id, span))
            unresolved.append(
                _unresolved(span, dynamic_id, "dynamic or unsupported registration form")
            )

    return SpikeArtifact(
        tuple(observations),
        tuple(scopes),
        tuple(composition_edges),
        tuple(associations),
        tuple(unresolved),
    )


def _span(file: str, start_line: int, start_column: int, end_line: int, end_column: int) -> SourceSpan:
    return SourceSpan(file, start_line, start_column, end_line, end_column)


def _match_span(file: str, line: int, match: re.Match[str]) -> SourceSpan:
    return _span(file, line, match.start() + 1, line, match.end() + 1)


def _observation(kind: str, identifier: str, span: SourceSpan, **attributes: str) -> Observation:
    return Observation(identifier, kind, span, tuple(sorted(attributes.items())))


def _unresolved(span: SourceSpan, subject_id: str | None, reason: str) -> UnresolvedObservation:
    return UnresolvedObservation(f"unresolved:{span.start_line}", subject_id, reason, span)


def _inline_middleware(tail: str) -> tuple[str, ...]:
    arguments = tail.split(",")[:-1]
    return tuple(argument.strip() for argument in arguments if re.fullmatch(r"[A-Za-z_$][\w$]*", argument.strip()))


def _handler_reference(tail: str) -> str | None:
    handler = tail.split(",")[-1].strip()
    return handler if re.fullmatch(r"[A-Za-z_$][\w$]*", handler) else None


def _normalized_path(receiver: str, path: str, mounts: dict[str, tuple[str, str, SourceSpan]]) -> str:
    prefixes = [path]
    seen: set[str] = set()
    while receiver in mounts and receiver not in seen:
        seen.add(receiver)
        receiver, prefix, _span = mounts[receiver]
        prefixes.append(prefix)
    return "/" + "/".join(part.strip("/") for part in reversed(prefixes) if part.strip("/"))
