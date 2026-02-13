import pathlib

text = pathlib.Path('src/authmapper/core/engine.py').read_text(encoding='utf-8')
lines = text.splitlines()
start = next(i for i, l in enumerate(lines) if 'def _analyze(' in l)
analyzer_methods = lines[start:]

out = [
    '"""Regex-based analyzer."""',
    'from __future__ import annotations',
    'import re',
    'from typing import Any',
    'from .analyzer import Analyzer',
    'from .model import AuthState, Confidence, Endpoint, Evidence, Finding, Severity',
    'from .rulepack import ENDPOINT_MODEL_FILE, SCOPE_SAME_LINE, RulePack',
    'from .safety import SafeMatcher, redact',
    'from .walker import SourceFile',
    '',
    'class RegexAnalyzer(Analyzer):',
    '    def __init__(self, matcher: SafeMatcher) -> None:',
    '        self._matcher = matcher',
    '',
    '    def analyze(self, source: SourceFile, pack: RulePack) -> list[Finding]:',
    '        return self._analyze(source, pack)',
    ''
]

pathlib.Path('src/authmapper/core/regex_analyzer.py').write_text('\n'.join(out) + '\n' + '\n'.join(analyzer_methods), encoding='utf-8')
