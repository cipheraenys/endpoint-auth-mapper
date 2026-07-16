"""Shared parser frontends for framework adapters."""

from .javascript import (
    JavaScriptAnalysis,
    JavaScriptExport,
    JavaScriptFailureCoverage,
    JavaScriptFrontend,
    JavaScriptFrontendResult,
    JavaScriptImport,
    JavaScriptModuleSummary,
    JavaScriptSource,
    JavaScriptSyntax,
    PackageBoundary,
)

__all__ = [
    "JavaScriptAnalysis",
    "JavaScriptExport",
    "JavaScriptFailureCoverage",
    "JavaScriptFrontend",
    "JavaScriptFrontendResult",
    "JavaScriptImport",
    "JavaScriptModuleSummary",
    "JavaScriptSource",
    "JavaScriptSyntax",
    "PackageBoundary",
]
