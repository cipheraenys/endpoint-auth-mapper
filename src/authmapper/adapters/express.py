"""Parser-backed Express adapter with package-local activation provenance."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from tree_sitter import Node

from authmapper.core.v2 import (
    ActivationEvidence,
    AdapterArtifact,
    AdapterInput,
    ApplicabilityResult,
    ApplicabilityState,
    Diagnostic,
    DiagnosticLevel,
    Fact,
    FactKind,
    Relation,
    RelationKind,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
    UnresolvedRecord,
)
from authmapper.frontends.javascript import (
    MAX_SOURCE_BYTES,
    JavaScriptFrontend,
    JavaScriptSource,
    default_export,
    module_bindings,
    resolve_local_module,
)

__all__ = ["ExpressAdapter", "MAX_SOURCE_BYTES"]

_DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
_ROUTE_METHODS = frozenset({"all", "delete", "get", "head", "options", "patch", "post", "put", "use"})
_ParsedSource = JavaScriptSource


@dataclass(frozen=True, slots=True)
class _FileEvidence:
    subjects: tuple[Subject, ...]
    facts: tuple[Fact, ...]
    scopes: tuple[Scope, ...]
    relations: tuple[Relation, ...]
    unresolved: tuple[UnresolvedRecord, ...]


@dataclass(frozen=True, slots=True)
class _RouteCall:
    receiver_name: str
    methods: tuple[tuple[str, Node], ...]
    path_node: Node | None


class ExpressAdapter:
    """Analyze supported JavaScript without executing Node or target code."""

    id = "express"
    version = "0.1.0"

    def applicability(self, input_data: AdapterInput) -> ApplicabilityResult:
        parsed, diagnostics = self._parse_inputs(input_data)
        evidence: list[ActivationEvidence] = []
        reasons: list[str] = []
        active_files = 0

        for item in parsed:
            if item.package_error:
                reasons.append(f"{item.relative_path}: {item.package_error}")
                continue
            if item.package_path is None or item.package_data is None:
                reasons.append(f"{item.relative_path}: no owning package.json")
                continue
            if not _has_express_dependency(item.package_data):
                reasons.append(f"{item.relative_path}: owning package does not declare express")
                continue

            bindings = _express_bindings(item.root, item.source)
            if not bindings:
                reasons.append(f"{item.relative_path}: no resolved Express import or require")
                continue
            active_files += 1
            package_relative = _relative(item.package_path, input_data.project_root)
            evidence.append(
                ActivationEvidence(
                    id=f"activation:package:{package_relative}",
                    kind="package_dependency",
                    value=f"{package_relative}:express",
                )
            )
            for name, node in bindings:
                evidence.append(
                    ActivationEvidence(
                        id=f"activation:binding:{item.relative_path}:{node.start_byte}:{name}",
                        kind="express_binding",
                        value=name,
                        span=_span(item.relative_path, node),
                    )
                )

        unique_evidence = {item.id: item for item in evidence}
        if diagnostics:
            state = ApplicabilityState.AMBIGUOUS
            reasons.extend(item.message for item in diagnostics)
        elif active_files:
            state = ApplicabilityState.ACTIVE
            reasons.append(f"resolved Express ownership in {active_files} source file(s)")
        else:
            state = ApplicabilityState.INACTIVE
        return ApplicabilityResult(
            adapter_id=self.id,
            state=state,
            evidence=tuple(unique_evidence[key] for key in sorted(unique_evidence)),
            reasons=tuple(sorted(set(reasons))),
        )

    def analyze(self, input_data: AdapterInput) -> AdapterArtifact:
        """Extract supported route and local mount evidence."""
        frontend = JavaScriptFrontend().analyze(input_data)
        parsed = frontend.sources
        diagnostic_list = [_express_diagnostic(item) for item in frontend.diagnostics]
        for item in parsed:
            unresolved_route = _first_unowned_route_call(item)
            if unresolved_route is not None:
                diagnostic_list.append(
                    Diagnostic(
                        id=f"diagnostic:express:binding:{item.relative_path}",
                        level=DiagnosticLevel.ERROR,
                        code="express.route.unresolved_binding",
                        message=f"route-like calls lack a resolved Express binding: {item.relative_path}",
                        span=_span(item.relative_path, unresolved_route),
                    )
                )
        diagnostics = tuple(sorted(diagnostic_list, key=lambda item: item.id))
        applicability = self.applicability(input_data)
        if applicability.state is ApplicabilityState.AMBIGUOUS and not diagnostics:
            diagnostics = (
                Diagnostic(
                    id="diagnostic:express:applicability",
                    level=DiagnosticLevel.ERROR,
                    code="express.applicability.ambiguous",
                    message="Express applicability could not be established",
                ),
            )
        active_parsed = tuple(item for item in parsed if _source_is_active(item))
        evidence = [_extract_file(item) for item in active_parsed]
        external_subjects, external_relations, external_mounts = _external_mounts(
            active_parsed, evidence, input_data.project_root.resolve()
        )
        local_relations = tuple(item for group in evidence for item in group.relations)
        graph_relation_ids = {item.id for item in (*external_relations, *local_relations)}
        facts = [item for group in evidence for item in group.facts]
        normalized_facts: list[Fact] = []
        subjects = {item.id: item for group in evidence for item in (*group.subjects, *external_subjects)}
        for fact in facts:
            if fact.kind is not FactKind.ENDPOINT_DECLARATION:
                normalized_facts.append(fact)
                continue
            receiver_id = subjects[fact.subject_id].parent_id
            prefix, relation_ids, ambiguous = _external_mount_path(receiver_id, external_mounts)
            if ambiguous:
                normalized_facts.append(fact)
                continue
            normalized_facts.append(
                replace(
                    fact,
                    path=_join_paths(prefix, fact.path or ""),
                    derived_from=tuple(
                        sorted(
                            reference
                            for reference in (*fact.derived_from, *relation_ids)
                            if reference in graph_relation_ids
                        )
                    ),
                )
            )
        return AdapterArtifact(
            subjects=_ordered((*external_subjects, *(item for group in evidence for item in group.subjects))),
            facts=_ordered(normalized_facts),
            scopes=_ordered(item for group in evidence for item in group.scopes),
            relations=_ordered((*external_relations, *local_relations)),
            unresolved=_ordered(item for group in evidence for item in group.unresolved),
            diagnostics=diagnostics,
        )

    def _parse_inputs(self, input_data: AdapterInput) -> tuple[tuple[_ParsedSource, ...], tuple[Diagnostic, ...]]:
        result = JavaScriptFrontend().parse(input_data)
        return result.sources, tuple(_express_diagnostic(item) for item in result.diagnostics)


def _express_diagnostic(diagnostic: Diagnostic) -> Diagnostic:
    """Keep frozen Express diagnostic codes while parsing moves to the frontend."""
    code = {
        "frontend.javascript.package_invalid": "express.package.invalid",
        "frontend.javascript.parse_error": "express.source.parse_error",
        "frontend.javascript.resource_limit": "express.budget.source_bytes",
        "frontend.javascript.unsupported_source": "express.source.unsupported",
    }.get(diagnostic.code, diagnostic.code)
    return replace(diagnostic, id=diagnostic.id.replace(":frontend:javascript:", ":express:"), code=code)


def _has_express_dependency(package: dict[str, Any]) -> bool:
    return any(isinstance(package.get(field), dict) and "express" in package[field] for field in _DEPENDENCY_FIELDS)


def _express_bindings(root: Node, source: bytes) -> tuple[tuple[str, Node], ...]:
    bindings: list[tuple[str, Node]] = []
    for node in _walk(root):
        if node.type == "import_statement":
            module = node.child_by_field_name("source")
            if module is None or _text(module, source).strip("'\"") != "express":
                continue
            clause = next((child for child in node.named_children if child.type == "import_clause"), None)
            if clause is not None:
                identifier = next((child for child in clause.named_children if child.type == "identifier"), None)
                if identifier is not None:
                    bindings.append((_text(identifier, source), identifier))
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                name is not None
                and name.type == "identifier"
                and value is not None
                and (_is_express_require(value, source) or _is_express_router_require(value, source))
            ):
                bindings.append((_text(name, source), name))
    return tuple(bindings)


def _is_express_router_require(node: Node, source: bytes) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or function.type != "member_expression":
        return False
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    return (
        obj is not None
        and prop is not None
        and _text(prop, source) == "Router"
        and _is_express_require(obj, source)
    )


def _source_is_active(item: _ParsedSource) -> bool:
    return (
        item.package_data is not None
        and item.package_error is None
        and _has_express_dependency(item.package_data)
        and bool(_express_bindings(item.root, item.source))
    )


def _first_unowned_route_call(item: _ParsedSource) -> Node | None:
    if item.package_data is None or item.package_error is not None or not _has_express_dependency(item.package_data):
        return None
    express_bindings = _express_bindings(item.root, item.source)
    if express_bindings:
        return None
    source_text = item.source.decode("utf-8")
    if "module.exports" not in source_text:
        return None
    for node in _walk(item.root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or function.type != "member_expression":
            continue
        receiver = function.child_by_field_name("object")
        method = function.child_by_field_name("property")
        if receiver is None or method is None or receiver.type != "identifier":
            continue
        if _text(receiver, item.source) not in {"app", "application", "router"}:
            continue
        if _text(method, item.source) in _ROUTE_METHODS and len(arguments.named_children) >= 2:
            return node
    return None


def _external_mounts(
    parsed: tuple[_ParsedSource, ...], evidence: list[_FileEvidence], project_root: Path
) -> tuple[tuple[Subject, ...], tuple[Relation, ...], dict[str, list[tuple[str, str, str]]]]:
    active = list(zip(parsed, evidence, strict=True))
    receivers: dict[tuple[Path, str], tuple[Subject, Scope]] = {}
    exports: dict[Path, tuple[Subject, Scope]] = {}
    for item, artifact in active:
        scopes = {scope.subject_id: scope for scope in artifact.scopes}
        local = {
            subject.name: (subject, scopes[subject.id])
            for subject in artifact.subjects
            if subject.kind is SubjectKind.OBJECT_PROPERTY and subject.name is not None
        }
        receivers.update({(item.path, name): value for name, value in local.items()})
        exported_name = _exported_receiver(item.root, item.source)
        if exported_name in local:
            exports[item.path] = local[exported_name]

    callback_receivers: dict[tuple[Path, str], tuple[Subject, Scope]] = {}
    exported_callbacks = {
        item.path: callback
        for item, _ in active
        if (callback := _exported_callback(item)) is not None
    }
    for item, _ in active:
        imports = _local_imports(item, project_root)
        for node in _walk(item.root):
            if node.type != "call_expression":
                continue
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is None or arguments is None or function.type != "identifier":
                continue
            target = imports.get(_text(function, item.source))
            callback = exported_callbacks.get(target) if target is not None else None
            args = arguments.named_children
            if callback is None or len(args) != 1 or args[0].type != "identifier":
                continue
            caller = receivers.get((item.path, _text(args[0], item.source)))
            if caller is not None and target is not None:
                callback_receivers[(target, callback)] = caller

    # Resolve package-local imported routers to a fixed point so nested mounts
    # work regardless of source path ordering.
    changed = True
    while changed:
        changed = False
        for item, artifact in active:
            if item.path in exports:
                continue
            scopes = {scope.subject_id: scope for scope in artifact.scopes}
            local = {
                subject.name: (subject, scopes[subject.id])
                for subject in artifact.subjects
                if subject.kind is SubjectKind.OBJECT_PROPERTY and subject.name is not None
            }
            exported_name = _exported_receiver(item.root, item.source)
            if exported_name in local:
                exports[item.path] = local[exported_name]
                changed = True

    for item, _ in active:
        imports = _local_imports(item, project_root)
        exported_name = _exported_receiver(item.root, item.source)
        if exported_name is not None and exported_name in imports and imports[exported_name] in exports:
            exports[item.path] = exports[imports[exported_name]]

    subjects: list[Subject] = []
    relations: list[Relation] = []
    mounts: dict[str, list[tuple[str, str, str]]] = {}
    for item, _ in active:
        imports = _local_imports(item, project_root)
        direct_mounts: dict[str, tuple[str, tuple[Subject, Scope]]] = {}
        for node in _walk(item.root):
            if node.type != "call_expression":
                continue
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is None or arguments is None:
                continue
            call = _external_mount_call(function, arguments, item.source)
            if call is None:
                continue
            parent_name, prefix_node, middleware_nodes, child_node = call
            callback_parent = callback_receivers.get((item.path, parent_name))
            parent = receivers.get((item.path, parent_name)) or callback_parent
            child_name = _text(child_node, item.source)
            child_path = imports.get(child_name)
            if child_path is None:
                module = _local_require_module(child_node, item.source)
                package_root = item.package_path.parent if item.package_path else project_root
                child_path = resolve_local_module(item.path, module, package_root) if module is not None else None
            child = (
                exports.get(child_path)
                if child_path is not None
                else receivers.get((item.path, child_name)) if callback_parent is not None else None
            )
            prefix = "" if prefix_node is None else _literal_string(prefix_node, item.source)
            if parent is None or child is None or prefix is None:
                continue
            relation = Relation(
                _id("relation", item.relative_path, node, "module-mount"),
                RelationKind.COMPOSES,
                parent[1].id,
                child[1].id,
                _span(item.relative_path, node),
            )
            relations.append(relation)
            mounts.setdefault(child[0].id, []).append((parent[0].id, prefix, relation.id))
            direct_mounts[child_name] = (prefix, child)
            _append_external_mount_middleware(
                item,
                child,
                node,
                middleware_nodes,
                subjects,
                relations,
            )
        for parent_name, prefix, child_name, node in _array_mount_calls(item):
            parent = receivers.get((item.path, parent_name))
            child_path = imports.get(child_name)
            child = exports.get(child_path) if child_path is not None else None
            if parent is None or child is None:
                continue
            relation = Relation(
                _id("relation", item.relative_path, node, f"array-mount-{child_name}"),
                RelationKind.COMPOSES,
                parent[1].id,
                child[1].id,
                _span(item.relative_path, node),
            )
            relations.append(relation)
            mounts.setdefault(child[0].id, []).append((parent[0].id, prefix, relation.id))
    return _ordered(subjects), _ordered(relations), mounts


def _append_external_mount_middleware(
    item: _ParsedSource,
    child: tuple[Subject, Scope],
    mount_node: Node,
    middleware_nodes: tuple[Node, ...],
    subjects: list[Subject],
    relations: list[Relation],
) -> None:
    passport_names = {name for name, _ in module_bindings(item.root, item.source, "passport")}
    custom_auth_names = _custom_auth_names(item)
    for index, middleware_node in enumerate(middleware_nodes):
        subject = Subject(
            _id("subject", item.relative_path, middleware_node, f"mount-middleware-{index}"),
            SubjectKind.MIDDLEWARE,
            _span(item.relative_path, middleware_node),
            parent_id=child[0].id,
            name=_middleware_name(middleware_node, item.source, passport_names, custom_auth_names),
        )
        subjects.append(subject)
        relations.append(
            Relation(
                _id("relation", item.relative_path, mount_node, f"mount-middleware-{index}"),
                RelationKind.CONTAINS,
                child[1].id,
                subject.id,
                subject.span,
                order=0,
            )
        )


def _exported_receiver(root: Node, source: bytes) -> str | None:
    return default_export(root, source)


def _exported_callback(item: _ParsedSource) -> str | None:
    exported_name = _exported_receiver(item.root, item.source)
    if exported_name is None:
        return None
    for node in _walk(item.root):
        if node.type != "function_declaration":
            continue
        name = node.child_by_field_name("name")
        parameters = node.child_by_field_name("parameters")
        if name is None or parameters is None or _text(name, item.source) != exported_name:
            continue
        identifiers = [child for child in parameters.named_children if child.type == "identifier"]
        if len(identifiers) == 1:
            return _text(identifiers[0], item.source)
    return None


def _array_mount_calls(item: _ParsedSource) -> tuple[tuple[str, str, str, Node], ...]:
    arrays: dict[str, tuple[tuple[str, str], ...]] = {}
    for node in _walk(item.root):
        if node.type != "variable_declarator":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier" or value.type != "array":
            continue
        entries: list[tuple[str, str]] = []
        for object_node in value.named_children:
            if object_node.type != "object":
                continue
            fields: dict[str, Node] = {}
            for pair in object_node.named_children:
                if pair.type != "pair":
                    continue
                key = pair.child_by_field_name("key")
                field_value = pair.child_by_field_name("value")
                if key is not None and field_value is not None:
                    fields[_text(key, item.source)] = field_value
            prefix = _literal_string(fields.get("path"), item.source)
            child = fields.get("route")
            if prefix is not None and child is not None and child.type == "identifier":
                entries.append((prefix, _text(child, item.source)))
        if entries:
            arrays[_text(name, item.source)] = tuple(entries)

    mounts: list[tuple[str, str, str, Node]] = []
    for node in _walk(item.root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or function.type != "member_expression":
            continue
        obj = function.child_by_field_name("object")
        prop = function.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier" or _text(prop, item.source) != "forEach":
            continue
        array_entries = arrays.get(_text(obj, item.source))
        callbacks = arguments.named_children
        if array_entries is None or len(callbacks) != 1 or callbacks[0].type != "arrow_function":
            continue
        callback = callbacks[0]
        parameters = callback.child_by_field_name("parameters")
        if parameters is None or parameters.type != "formal_parameters":
            continue
        identifiers = [child for child in parameters.named_children if child.type == "identifier"]
        if len(identifiers) != 1:
            continue
        parameter = identifiers[0]
        parameter_name = _text(parameter, item.source)
        for nested in _walk(callback):
            if nested.type != "call_expression":
                continue
            nested_function = nested.child_by_field_name("function")
            nested_arguments = nested.child_by_field_name("arguments")
            if nested_function is None or nested_arguments is None or nested_function.type != "member_expression":
                continue
            parent = nested_function.child_by_field_name("object")
            method = nested_function.child_by_field_name("property")
            args = nested_arguments.named_children
            if parent is None or method is None or parent.type != "identifier" or _text(method, item.source) != "use":
                continue
            if len(args) != 2:
                continue
            expected = (f"{parameter_name}.path", f"{parameter_name}.route")
            if tuple(_text(arg, item.source) for arg in args) != expected:
                continue
            mounts.extend(
                (_text(parent, item.source), prefix, child, nested)
                for prefix, child in array_entries
            )
    return tuple(mounts)


def _local_imports(item: _ParsedSource, project_root: Path) -> dict[str, Path]:
    return {
        binding.local_name: binding.target
        for binding in JavaScriptFrontend().local_modules(item, project_root)
        if binding.target is not None
    }


def _external_mount_path(
    receiver_id: str | None,
    mounts: dict[str, list[tuple[str, str, str]]],
    seen: frozenset[str] = frozenset(),
) -> tuple[str, tuple[str, ...], bool]:
    if receiver_id is None or receiver_id not in mounts:
        return "", (), False
    if receiver_id in seen or len(mounts[receiver_id]) != 1:
        return "", tuple(item[2] for item in mounts[receiver_id]), True
    parent_id, prefix, relation_id = mounts[receiver_id][0]
    parent_prefix, relation_ids, ambiguous = _external_mount_path(parent_id, mounts, seen | {receiver_id})
    return _join_paths(parent_prefix, prefix), tuple((*relation_ids, relation_id)), ambiguous


def _extract_file(item: _ParsedSource) -> _FileEvidence:
    express_names = {name for name, _ in _express_bindings(item.root, item.source)}
    passport_names = {name for name, _ in module_bindings(item.root, item.source, "passport")}
    custom_auth_names = _custom_auth_names(item)
    receivers: dict[str, tuple[str, Subject, Scope]] = {}
    subjects: list[Subject] = []
    facts: list[Fact] = []
    scopes: list[Scope] = []
    relations: list[Relation] = []
    unresolved: list[UnresolvedRecord] = []
    route_receivers: dict[str, str] = {}
    mounts: dict[str, list[tuple[str, str, str]]] = {}

    for node in _walk(item.root):
        if node.type != "variable_declarator":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or name.type != "identifier" or value is None:
            continue
        receiver_kind = _receiver_kind(value, item.source, express_names)
        if receiver_kind is None:
            continue
        receiver_name = _text(name, item.source)
        if receiver_name in receivers:
            unresolved.append(
                UnresolvedRecord(
                    _id("unresolved", item.relative_path, node, "duplicate-receiver"),
                    "duplicate Express receiver declaration",
                    None,
                    _span(item.relative_path, node),
                )
            )
            receivers.pop(receiver_name)
            continue
        kind, scope_kind = receiver_kind
        subject = Subject(
            _id("subject", item.relative_path, node, receiver_name),
            kind,
            _span(item.relative_path, node),
            name=receiver_name,
        )
        scope = Scope(
            _id("scope", item.relative_path, node, receiver_name),
            scope_kind,
            subject.id,
            subject.span,
        )
        receivers[receiver_name] = (receiver_name, subject, scope)
        subjects.append(subject)
        scopes.append(scope)

    order = 0
    for node in _walk(item.root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        if _is_inner_route_chain_call(node, item.source):
            continue
        route = _route_call(function, item.source)
        if route is not None:
            receiver_name = route.receiver_name
            if receiver_name not in receivers:
                continue
            if (
                route.path_node is not None
                and route.path_node in arguments.named_children
                and len(arguments.named_children) < 2
            ):
                continue
            path = "/" if route.path_node is None else _literal_string(route.path_node, item.source)
            if path is None:
                unresolved.append(
                    UnresolvedRecord(
                        _id("unresolved", item.relative_path, node, "dynamic-route"),
                        "computed or unsupported route path",
                        receivers[receiver_name][1].id,
                        _span(item.relative_path, node),
                    )
                )
                continue
            for method, method_arguments in route.methods:
                order += 1
                route_node = method_arguments.parent or node
                route_subject = Subject(
                    _id("subject", item.relative_path, route_node, f"route-{method}"),
                    SubjectKind.ROUTE_CALL,
                    _span(item.relative_path, route_node),
                    parent_id=receivers[receiver_name][1].id,
                    name=f"{receiver_name}.{method}",
                )
                endpoint = Fact(
                    _id("fact", item.relative_path, route_node, f"endpoint-{method}"),
                    FactKind.ENDPOINT_DECLARATION,
                    route_subject.id,
                    route_subject.span,
                    method="ALL" if method in {"all", "use"} else method.upper(),
                    path=path,
                )
                route_scope = Scope(
                    _id("scope", item.relative_path, route_node, f"route-{method}"),
                    ScopeKind.ROUTE,
                    route_subject.id,
                    route_subject.span,
                    parent_id=receivers[receiver_name][2].id,
                )
                subjects.append(route_subject)
                facts.append(endpoint)
                route_receivers[endpoint.id] = receivers[receiver_name][1].id
                public = _public_declaration(item, route_node, route_subject)
                if public is not None:
                    public_subject, public_fact = public
                    subjects.append(public_subject)
                    facts.append(public_fact)
                    relations.append(
                        Relation(
                            _id("relation", item.relative_path, route_node, f"public-{method}"),
                            RelationKind.REFERENCES,
                            route_subject.id,
                            public_subject.id,
                            public_subject.span,
                        )
                    )
                scopes.append(route_scope)
                relations.append(
                    Relation(
                        _id("relation", item.relative_path, route_node, f"registration-{method}"),
                        RelationKind.CONTAINS,
                        receivers[receiver_name][2].id,
                        route_scope.id,
                        route_subject.span,
                        order=order,
                    )
                )
                handlers = tuple(method_arguments.named_children)
                if route.path_node is not None and route.path_node in method_arguments.named_children:
                    handlers = handlers[1:]
                for index, handler in enumerate(handlers):
                    is_middleware = index < len(handlers) - 1
                    handler_node = handler
                    if handler.type == "call_expression":
                        handler_node = handler.child_by_field_name("function") or handler
                    handler_subject = Subject(
                        _id("subject", item.relative_path, handler, f"handler-{method}"),
                        SubjectKind.MIDDLEWARE if is_middleware else SubjectKind.HANDLER,
                        _span(item.relative_path, handler),
                        parent_id=route_subject.id,
                        name=_middleware_name(handler_node, item.source, passport_names, custom_auth_names),
                    )
                    subjects.append(handler_subject)
                    relations.append(
                        Relation(
                            _id("relation", item.relative_path, handler, f"handler-{method}"),
                            RelationKind.REFERENCES,
                            route_subject.id,
                            handler_subject.id,
                            handler_subject.span,
                            order=index,
                        )
                    )
                if method == "use" and route.path_node is None:
                    unresolved.append(
                        UnresolvedRecord(
                            _id("unresolved", item.relative_path, route_node, "catch-all-dispatch"),
                            "catch-all handler dispatch semantics are unresolved",
                            endpoint.id,
                            route_subject.span,
                        )
                    )
            continue

        mount = _mount_call(function, arguments, item.source)
        middleware = _middleware_call(function, arguments, item.source)
        if mount is None and middleware is None:
            continue
        if middleware is not None:
            receiver_name, middleware_node = middleware
            if receiver_name not in receivers:
                continue
            order += 1
            middleware_subject = Subject(
                _id("subject", item.relative_path, middleware_node, "middleware"),
                SubjectKind.MIDDLEWARE,
                _span(item.relative_path, middleware_node),
                parent_id=receivers[receiver_name][1].id,
                name=_middleware_name(middleware_node, item.source, passport_names, custom_auth_names),
            )
            subjects.append(middleware_subject)
            relations.append(
                Relation(
                    _id("relation", item.relative_path, node, "middleware"),
                    RelationKind.CONTAINS,
                    receivers[receiver_name][2].id,
                    middleware_subject.id,
                    middleware_subject.span,
                    order=order,
                )
            )
            continue
        assert mount is not None
        parent_name, prefix_node, child_name = mount
        if parent_name not in receivers or child_name not in receivers:
            continue
        order += 1
        prefix = _literal_string(prefix_node, item.source)
        if prefix is None:
            unresolved.append(
                UnresolvedRecord(
                    _id("unresolved", item.relative_path, node, "dynamic-mount"),
                    "computed or unsupported mount prefix",
                    receivers[child_name][1].id,
                    _span(item.relative_path, node),
                )
            )
            continue
        relations.append(
            Relation(
                _id("relation", item.relative_path, node, "mount"),
                RelationKind.COMPOSES,
                receivers[parent_name][2].id,
                receivers[child_name][2].id,
                _span(item.relative_path, node),
                order=order,
            )
        )
        mounts.setdefault(receivers[child_name][1].id, []).append(
            (receivers[parent_name][1].id, prefix, relations[-1].id)
        )

    normalized_facts: list[Fact] = []
    for fact in facts:
        receiver_id = route_receivers.get(fact.id)
        if receiver_id is None:
            normalized_facts.append(fact)
            continue
        prefix, mount_ids, ambiguous = _mount_path(receiver_id, mounts)
        handler_ids = tuple(
            relation.id
            for relation in relations
            if relation.kind is RelationKind.REFERENCES and relation.source_id == fact.subject_id
        )
        if ambiguous:
            unresolved.append(
                UnresolvedRecord(
                    f"unresolved:{fact.id}:ambiguous-mount",
                    "router has duplicate or ambiguous mount paths",
                    fact.id,
                    fact.span,
                    tuple(sorted(mount_ids)),
                )
            )
        normalized_facts.append(
            replace(
                fact,
                path=_join_paths(prefix, fact.path or ""),
                derived_from=tuple(sorted((*mount_ids, *handler_ids))),
            )
        )

    return _FileEvidence(
        _ordered(subjects),
        _ordered(normalized_facts),
        _ordered(scopes),
        _ordered(relations),
        _ordered(unresolved),
    )


def _receiver_kind(
    node: Node, source: bytes, express_names: set[str]
) -> tuple[SubjectKind, ScopeKind] | None:
    if _is_express_router_require(node, source):
        return SubjectKind.OBJECT_PROPERTY, ScopeKind.COMPONENT
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor")
        if constructor is None:
            return None
        if constructor.type == "identifier" and _text(constructor, source) in express_names:
            return SubjectKind.OBJECT_PROPERTY, ScopeKind.APPLICATION
        if constructor.type == "member_expression":
            obj = constructor.child_by_field_name("object")
            prop = constructor.child_by_field_name("property")
            if (
                obj is not None
                and prop is not None
                and _text(obj, source) in express_names
                and _text(prop, source) == "Router"
            ):
                return SubjectKind.OBJECT_PROPERTY, ScopeKind.COMPONENT
        return None
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "identifier" and _text(function, source) in express_names:
        return SubjectKind.OBJECT_PROPERTY, ScopeKind.APPLICATION
    if function.type == "member_expression":
        obj = function.child_by_field_name("object")
        prop = function.child_by_field_name("property")
        if (
            obj is not None
            and prop is not None
            and _text(obj, source) in express_names
            and _text(prop, source) == "Router"
        ):
            return SubjectKind.OBJECT_PROPERTY, ScopeKind.COMPONENT
    return None


def _route_call(function: Node, source: bytes) -> _RouteCall | None:
    if function.type != "member_expression":
        return None
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    if obj is None or prop is None:
        return None
    method = _text(prop, source)
    if method not in _ROUTE_METHODS:
        return None
    if obj.type == "identifier":
        arguments = function.parent.child_by_field_name("arguments") if function.parent is not None else None
        if arguments is None:
            return None
        args = arguments.named_children
        if method == "use":
            handler_types = {"arrow_function", "function_expression"}
            if len(args) == 1 and args[0].type in handler_types:
                return _RouteCall(_text(obj, source), ((method, arguments),), None)
            if len(args) >= 2 and args[-1].type in handler_types:
                return _RouteCall(_text(obj, source), ((method, arguments),), args[0])
            return None
        path_node = _first_argument(arguments)
        if path_node is not None:
            return _RouteCall(_text(obj, source), ((method, arguments),), path_node)
        return None
    methods: list[tuple[str, Node]] = []
    current = function.parent
    while current is not None and current.type == "call_expression":
        current_function = current.child_by_field_name("function")
        current_arguments = current.child_by_field_name("arguments")
        if current_function is None or current_arguments is None or current_function.type != "member_expression":
            return None
        current_object = current_function.child_by_field_name("object")
        current_property = current_function.child_by_field_name("property")
        if current_object is None or current_property is None:
            return None
        current_method = _text(current_property, source)
        if current_method in _ROUTE_METHODS:
            methods.append((current_method, current_arguments))
            current = current_object
            continue
        if current_method != "route" or current_object.type != "identifier":
            return None
        path_node = _first_argument(current_arguments)
        if path_node is None:
            return None
        return _RouteCall(_text(current_object, source), tuple(reversed(methods)), path_node)
    return None


def _is_inner_route_chain_call(node: Node, source: bytes) -> bool:
    parent = node.parent
    if parent is None or parent.type != "member_expression" or parent.child_by_field_name("object") != node:
        return False
    outer_call = parent.parent
    property_node = parent.child_by_field_name("property")
    return (
        outer_call is not None
        and outer_call.type == "call_expression"
        and property_node is not None
        and _text(property_node, source) in _ROUTE_METHODS
    )


def _mount_call(function: Node, arguments: Node, source: bytes) -> tuple[str, Node, str] | None:
    if function.type != "member_expression":
        return None
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    args = arguments.named_children
    if (
        obj is None
        or prop is None
        or obj.type != "identifier"
        or _text(prop, source) != "use"
        or len(args) != 2
    ):
        return None
    if args[1].type != "identifier":
        return None
    return _text(obj, source), args[0], _text(args[1], source)


def _external_mount_call(
    function: Node, arguments: Node, source: bytes
) -> tuple[str, Node | None, tuple[Node, ...], Node] | None:
    if function.type != "member_expression":
        return None
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    args = arguments.named_children
    if (
        obj is None
        or prop is None
        or obj.type != "identifier"
        or _text(prop, source) != "use"
        or not args
        or args[-1].type not in {"identifier", "call_expression"}
    ):
        return None
    if args[-1].type == "call_expression" and _local_require_module(args[-1], source) is None:
        return None
    if len(args) == 1:
        return _text(obj, source), None, (), args[0]
    return _text(obj, source), args[0], tuple(args[1:-1]), args[-1]


def _local_require_module(node: Node, source: bytes) -> str | None:
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or _text(function, source) != "require":
        return None
    return _literal_string(_first_argument(arguments), source)


def _middleware_call(function: Node, arguments: Node, source: bytes) -> tuple[str, Node] | None:
    if function.type != "member_expression":
        return None
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    args = arguments.named_children
    if (
        obj is None
        or prop is None
        or obj.type != "identifier"
        or _text(prop, source) != "use"
        or len(args) != 1
    ):
        return None
    return _text(obj, source), args[0]


def _first_argument(arguments: Node) -> Node | None:
    return arguments.named_children[0] if arguments.named_children else None


def _handler_arguments(arguments: Node, chained: bool) -> tuple[Node, ...]:
    args = tuple(arguments.named_children)
    return args if chained else args[1:]


def _literal_string(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type != "string":
        return None
    text = _text(node, source)
    return text[1:-1]


def _middleware_name(
    node: Node,
    source: bytes,
    passport_names: set[str],
    custom_auth_names: dict[str, str],
) -> str:
    text = _text(node, source)
    if node.type == "identifier" and text in custom_auth_names:
        semantic = custom_auth_names[text]
        return semantic if semantic.startswith("unresolved-auth:") else f"custom-auth:{semantic}"
    if node.type == "member_expression":
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        if object_node is not None and property_node is not None:
            member_name = f"{_text(object_node, source)}.{_text(property_node, source)}"
            if member_name == "passport.authenticate" and _text(object_node, source) in passport_names:
                return _passport_authenticate_name(node.parent, source)
            if member_name in custom_auth_names:
                return f"custom-auth:{custom_auth_names[member_name]}"
            return f"custom-member:{member_name}"
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is not None:
            if function.type == "member_expression":
                object_node = function.child_by_field_name("object")
                property_node = function.child_by_field_name("property")
                if object_node is not None and property_node is not None:
                    member_name = f"{_text(object_node, source)}.{_text(property_node, source)}"
                    if member_name == "passport.authenticate" and _text(object_node, source) in passport_names:
                        return _passport_authenticate_name(node, source)
                    if member_name in custom_auth_names:
                        return f"custom-auth:{custom_auth_names[member_name]}"
            return _middleware_name(function, source, passport_names, custom_auth_names)
    if node.type != "call_expression":
        return text
    function = node.child_by_field_name("function")
    if function is None or function.type != "member_expression":
        return text
    obj = function.child_by_field_name("object")
    prop = function.child_by_field_name("property")
    if obj is not None and prop is not None and _text(obj, source) in passport_names:
        return f"passport.{_text(prop, source)}"
    return text


def _passport_authenticate_name(node: Node | None, source: bytes) -> str:
    if node is None or node.type != "call_expression":
        return "passport.authenticate:unknown"
    arguments = node.child_by_field_name("arguments")
    strategy = _literal_string(_first_argument(arguments), source) if arguments is not None else None
    return f"passport.authenticate:{strategy or 'unknown'}"


def _custom_auth_names(item: _ParsedSource) -> dict[str, str]:
    imports = _local_imports(item, item.package_path.parent if item.package_path else item.path.parent)
    declarations: dict[str, str] = {}
    prefix = "// authmap-auth-v1 "
    for line in item.source.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        fields = dict(token.split("=", 1) for token in stripped[len(prefix) :].split() if "=" in token)
        symbol = fields.get("symbol")
        module = fields.get("module")
        rule = fields.get("rule")
        if not symbol or not module or not rule or symbol.split(".", 1)[0] not in imports:
            continue
        package_root = item.package_path.parent if item.package_path else item.path.parent
        resolved = resolve_local_module(item.path, module, package_root)
        if resolved is not None and imports[symbol.split(".", 1)[0]] == resolved:
            declarations[symbol] = rule
    for symbol, target in imports.items():
        if "auth" in target.name.lower() and any(token in symbol.lower() for token in ("auth", "apikey", "token")):
            declarations.setdefault(symbol, f"unresolved-auth:{target.name}:{symbol}")
    return declarations


def _public_declaration(
    item: _ParsedSource, route_node: Node, route_subject: Subject
) -> tuple[Subject, Fact] | None:
    if route_node.start_point.row == 0:
        return None
    lines = item.source.decode("utf-8").splitlines()
    declaration = lines[route_node.start_point.row - 1].strip()
    prefix = "// authmap-public-v1 "
    if not declaration.startswith(prefix):
        return None
    fields: dict[str, str] = {}
    for token in declaration[len(prefix) :].split():
        key, separator, value = token.partition("=")
        if separator and key in {"owner", "policy", "reason"} and value:
            fields[key] = value
    if set(fields) != {"owner", "policy", "reason"}:
        return None
    row = route_node.start_point.row
    span = SourceSpan(item.relative_path, row, 1, row, len(lines[row - 1]) + 1)
    subject = Subject(
        f"subject:{item.relative_path}:{route_node.start_byte:08d}:public",
        SubjectKind.PUBLIC_DECLARATION,
        span,
        name=f"v1:{fields['policy']}:{fields['owner']}:{fields['reason']}",
        parent_id=route_subject.id,
    )
    fact = Fact(
        f"fact:{item.relative_path}:{route_node.start_byte:08d}:public",
        FactKind.PUBLIC_DECLARATION,
        subject.id,
        span,
    )
    return subject, fact


def _id(kind: str, path: str, node: Node, label: str) -> str:
    return f"{kind}:{path}:{node.start_byte:08d}:{label}"


def _mount_path(
    receiver_id: str, mounts: dict[str, list[tuple[str, str, str]]], seen: frozenset[str] = frozenset()
) -> tuple[str, tuple[str, ...], bool]:
    if receiver_id in seen:
        return "", (), True
    entries = mounts.get(receiver_id, [])
    if not entries:
        return "", (), False
    if len(entries) != 1:
        return "", tuple(item[2] for item in entries), True
    parent_id, prefix, relation_id = entries[0]
    parent_prefix, relation_ids, ambiguous = _mount_path(parent_id, mounts, seen | {receiver_id})
    return _join_paths(parent_prefix, prefix), tuple((*relation_ids, relation_id)), ambiguous


def _join_paths(prefix: str, path: str) -> str:
    parts = [part.strip("/") for part in (prefix, path) if part.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


def _ordered(items):
    return tuple(sorted(items, key=lambda item: item.id))


def _is_express_require(node: Node, source: bytes) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or _text(function, source) != "require":
        return False
    named = arguments.named_children
    return len(named) == 1 and named[0].type == "string" and _text(named[0], source).strip("'\"") == "express"


def _walk(node: Node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _span(path: str, node: Node) -> SourceSpan:
    return SourceSpan(
        path,
        node.start_point.row + 1,
        node.start_point.column + 1,
        node.end_point.row + 1,
        node.end_point.column + 1,
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()
