import pathlib

text = pathlib.Path('engine_dump.txt').read_text(encoding='utf-8')
lines = text.splitlines()
start = next(i for i, l in enumerate(lines) if 'def _analyze(' in l)

# keep everything before start, but we also need to change imports
out = []
for line in lines[:start]:
    if 'from .model import' in line:
        out.append('from .model import ScanResult, ScanError, Finding, Endpoint, Confidence, AuthState, Severity, Evidence')
    elif 'from .rulepack import' in line:
        out.append('from .rulepack import RulePack, ENDPOINT_MODEL_FILE')
    elif 'from .safety import' in line:
        out.append('from .safety import SafeMatcher\nfrom .walker import FileWalker, SourceFile')
    else:
        out.append(line)

out.insert(12, 'from .analyzer import Analyzer')
out.insert(13, 'from .regex_analyzer import RegexAnalyzer')
out.insert(14, 'from .ast_analyzer import ASTAnalyzer')

# rewrite Engine
engine_code = '''
class Engine:
    """The analysis engine."""

    def __init__(self, rulepacks: Sequence[RulePack], config: EngineConfig | None = None) -> None:
        self._rulepacks = tuple(rulepacks)
        self._config = config or EngineConfig()
        self._matcher = SafeMatcher(self._config.regex_timeout_seconds)
        self._regex_analyzer = RegexAnalyzer(self._matcher)
        self._ast_analyzer = ASTAnalyzer()

    # -- public API ----------------------------------------------------------

    def scan(self, root: Path, *, extra_excludes: Sequence[str] = ()) -> ScanResult:
        """Analyze ``root`` and return an aggregate :class:`ScanResult`."""
        started = time.perf_counter()
        include_globs = self._all_globs()
        walker = FileWalker(
            root,
            include_globs=include_globs,
            extra_excludes=extra_excludes,
            max_file_bytes=self._config.max_file_bytes,
        )

        findings: list[Finding] = []
        errors: list[ScanError] = []
        scanned = 0

        for source in walker.walk():
            scanned += 1

            for pack in self._rulepacks:
                if pack.matches_file(source.relpath):
                    try:
                        file_findings = self._analyze_file(source, pack)
                        findings.extend(file_findings)
                    except Exception as exc:
                        errors.append(ScanError(f"{source.relpath} ({pack.name}): {exc}"))

        duration = time.perf_counter() - started
        return ScanResult(
            findings=tuple(findings),
            errors=tuple(errors),
            files_scanned=scanned,
            duration_seconds=duration,
        )

    # -- internals -----------------------------------------------------------

    def _all_globs(self) -> list[str]:
        globs: list[str] = []
        for pack in self._rulepacks:
            globs.extend(pack.file_globs)
        return globs

    def _analyze_file(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        if self._ast_analyzer.is_available() and pack.ast_endpoints:
            try:
                ast_findings = self._ast_analyzer.analyze(source, pack)
                if ast_findings:
                    return ast_findings
            except Exception as e:
                # Fallback to regex
                pass
        return self._regex_analyzer.analyze(source, pack)
'''

# Find class Engine
engine_start = next(i for i, l in enumerate(out) if 'class Engine:' in l)
final_out = out[:engine_start] + engine_code.splitlines()

pathlib.Path('src/authmapper/core/engine.py').write_text('\n'.join(final_out), encoding='utf-8')
