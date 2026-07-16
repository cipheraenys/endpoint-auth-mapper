"""Shared parser frontends for framework adapters."""

from .conformance import ClaimRole, OwnershipClaim, resolve_ownership
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
    "ClaimRole",
    "OwnershipClaim",
    "resolve_ownership",
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
