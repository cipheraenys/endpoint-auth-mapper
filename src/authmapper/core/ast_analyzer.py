"""AST-based analyzer."""

from __future__ import annotations

from typing import Any

from .analyzer import Analyzer
from .model import AuthState, Confidence, Endpoint, Evidence, Finding, Severity
from .rulepack import RulePack, SCOPE_SAME_LINE
from .walker import SourceFile


class ASTAnalyzer(Analyzer):
    """Analyzes source files using tree-sitter if available."""

    def __init__(self) -> None:
        self._tree_sitter_available = False
        self._parsers: dict[str, Any] = {}
        try:
            import tree_sitter
            self._tree_sitter = tree_sitter
            self._tree_sitter_available = True
        except ImportError:
            pass

    def is_available(self) -> bool:
        return self._tree_sitter_available

    def _get_parser(self, language: str) -> Any:
        if language in self._parsers:
            return self._parsers[language]
        
        try:
            # We assume tree-sitter-<lang> is installed
            lang_module = __import__(f"tree_sitter_{language}")
            lang = self._tree_sitter.Language(lang_module.language())
            parser = self._tree_sitter.Parser(lang)
            self._parsers[language] = (lang, parser)
            return lang, parser
        except ImportError as e:
            raise RuntimeError(f"Missing tree-sitter language '{language}': {e}")

    def analyze(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        if not self.is_available() or not pack.ast_language or not pack.ast_endpoints:
            return []

        lang, parser = self._get_parser(pack.ast_language)
        
        # Parse tree
        source_bytes = source.text.encode('utf-8')
        tree = parser.parse(source_bytes)

        # Execute endpoint queries
        endpoints_found = []
        for ep_pattern in pack.ast_endpoints:
            query = lang.query(ep_pattern.query)
            captures = query.captures(tree.root_node)
            
            # Group captures by match (simplified assumption: sequential non-overlapping matches)
            # A robust query execution would use query.matches()
            for match in query.matches(tree.root_node):
                method = "ANY"
                route = "/"
                line = 1
                
                # Extract @method and @route
                # match[1] is a dict of capture name -> node or list of nodes
                capture_dict = match[1]
                
                if "method" in capture_dict:
                    nodes = capture_dict["method"]
                    node = nodes[0] if isinstance(nodes, list) else nodes
                    method = source_bytes[node.start_byte:node.end_byte].decode('utf-8').strip('\'"`').upper()
                    line = node.start_point[0] + 1
                    
                if "route" in capture_dict:
                    nodes = capture_dict["route"]
                    node = nodes[0] if isinstance(nodes, list) else nodes
                    route = source_bytes[node.start_byte:node.end_byte].decode('utf-8').strip('\'"`')
                    line = node.start_point[0] + 1

                endpoint = Endpoint(
                    file=source.relpath,
                    line=line,
                    method=method,
                    route=route,
                    language=pack.language,
                    framework=pack.framework,
                )
                endpoints_found.append((endpoint, ep_pattern.rule_id))

        if not endpoints_found:
            return []

        # Find auth guards
        file_guards = []
        node_guards = [] # Node guards would require mapping to endpoint AST nodes, for simplicity we treat all guards found via AST as file-level or block-level if we implement it.
        # But wait, AST can be precise. Let's just do a basic implementation that replicates scope.
        
        for sig_pattern in pack.ast_auth_signals:
            query = lang.query(sig_pattern.query)
            for match in query.matches(tree.root_node):
                capture_dict = match[1]
                if "guard" in capture_dict:
                    nodes = capture_dict["guard"]
                    node = nodes[0] if isinstance(nodes, list) else nodes
                    snippet = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                    line_no = node.start_point[0] + 1
                    evidence = Evidence(
                        file=source.relpath,
                        line=line_no,
                        signal=sig_pattern.rule_id,
                        snippet=snippet,
                    )
                    file_guards.append(evidence)

        # Create findings
        findings = []
        for endpoint, rule_id in endpoints_found:
            # AST is high confidence by default
            state = AuthState.EXPOSED
            confidence = Confidence.HIGH
            severity = Severity.HIGH
            evidence = []
            
            if file_guards:
                state = AuthState.PROTECTED
                confidence = Confidence.HIGH
                severity = Severity.INFO
                evidence.extend(file_guards)
            
            # Check for generic suppressions or logic (for now, simplified)
            finding = Finding(
                endpoint=endpoint,
                auth_state=state,
                confidence=confidence,
                severity=severity,
                evidence=tuple(evidence),
                rationale=f"AST discovered via {rule_id}",
            )
            findings.append(finding)
            
        return findings
