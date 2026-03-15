"""Human-readable console table reporter.

Renders a scan result as an aligned, plain-text table plus a summary banner.
Color is applied only when writing to a TTY and is stripped otherwise, keeping
output clean in logs, files, and screen readers.
"""

from __future__ import annotations

import os
import sys

from ..core.model import AuthState, ScanResult, Severity

# ANSI colors, gated on TTY + absence of NO_COLOR (https://no-color.org).
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_STATE_COLOR = {
    AuthState.EXPOSED: "\033[31m",    # red
    AuthState.UNKNOWN: "\033[33m",    # yellow
    AuthState.PROTECTED: "\033[32m",  # green
    AuthState.PUBLIC: "\033[36m",     # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_RESET}"


def _bold(text: str) -> str:
    return _c(text, _BOLD)


def render_table(result: ScanResult) -> str:
    """Render ``result`` as a console report string."""
    lines: list[str] = []
    lines.append(_bold("Endpoint & Auth Mapper — report"))
    lines.append(
        "CONFIDENTIAL: contains unmitigated attack surface. Do not commit or share broadly."
    )
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No endpoints classified. (Check rule-pack coverage for this stack.)")
    else:
        lines.extend(_render_rows(result))

    lines.append("")
    lines.extend(_render_summary(result))
    if result.errors:
        lines.append("")
        lines.append(_bold(f"Scan warnings ({len(result.errors)}):"))
        for err in result.errors[:20]:
            lines.append(f"  ! {err.file}: {err.message}")
        if len(result.errors) > 20:
            lines.append(f"  ... and {len(result.errors) - 20} more")
    return "\n".join(lines)


def _render_rows(result: ScanResult) -> list[str]:
    rows: list[tuple[str, str, str, str, str]] = []
    for f in result.sorted_findings():
        ep = f.endpoint
        rows.append(
            (
                str(f.severity),
                str(f.auth_state),
                f"{ep.method} {ep.route}",
                f"{ep.file}:{ep.line}",
                str(f.confidence),
            )
        )

    headers = ("SEVERITY", "STATE", "ENDPOINT", "LOCATION", "CONF")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    out: list[str] = []
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out.append(_bold(header_line))
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))

    for f, row in zip(result.sorted_findings(), rows):
        color = _STATE_COLOR.get(f.auth_state, "")
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(row)]
        line = "  ".join(cells)
        out.append(_c(line, color) if color else line)
    return out


def _render_summary(result: ScanResult) -> list[str]:
    counts = result.counts_by_state()
    parts = [
        f"{_c('EXPOSED', _STATE_COLOR[AuthState.EXPOSED])}={counts['EXPOSED']}",
        f"{_c('UNKNOWN', _STATE_COLOR[AuthState.UNKNOWN])}={counts['UNKNOWN']}",
        f"{_c('PROTECTED', _STATE_COLOR[AuthState.PROTECTED])}={counts['PROTECTED']}",
        f"{_c('PUBLIC', _STATE_COLOR[AuthState.PUBLIC])}={counts['PUBLIC']}",
    ]
    summary = [
        _bold("Summary"),
        "  " + "  ".join(parts),
        f"  files scanned={result.files_scanned}  skipped={result.files_skipped}"
        f"  rulepacks={len(result.rulepacks_used)}  time={result.duration_seconds:.3f}s",
        f"  max severity={_severity_label(result.max_severity())}",
    ]
    return summary


def _severity_label(sev: Severity) -> str:
    return str(sev)
