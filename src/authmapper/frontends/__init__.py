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
from .rust import (
    CargoDependency,
    CargoPackage,
    RustAnalysis,
    RustFailureCoverage,
    RustFrontend,
    RustModule,
    RustModuleSummary,
    RustSource,
    RustSyntax,
    RustUse,
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
    "CargoDependency",
    "CargoPackage",
    "RustAnalysis",
    "RustFailureCoverage",
    "RustFrontend",
    "RustModule",
    "RustModuleSummary",
    "RustSource",
    "RustSyntax",
    "RustUse",
]
