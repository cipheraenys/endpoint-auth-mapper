"""Human-readable console table reporter.

Renders a scan result as an aligned, plain-text table plus a summary banner.
Color is applied only when writing to a TTY and is stripped otherwise, keeping
output clean in logs, files, and screen readers.
"""

from __future__ import annotations

import os
import sys

from ..core.model import AuthState, ScanResult, Severity

_STATE_COLOR = {
    AuthState.EXPOSED: "\033[31m",    # red
    AuthState.UNKNOWN: "\033[33m",    # yellow
    AuthState.PROTECTED: "\033[32m",  # green
    AuthState.PUBLIC: "\033[36m",     # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color() -> bool:
    """Check at call time whether stdout supports color output."""
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, color: str, *, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{_RESET}"


def _bold(text: str, *, use_color: bool) -> str:
    return _c(text, _BOLD, use_color=use_color)


def render_table(result: ScanResult) -> str:
    """Render ``result`` as a console report string."""
    color = _use_color()
    lines: list[str] = []
    lines.append(_bold("Endpoint & Auth Mapper — report", use_color=color))
    lines.append(
        "CONFIDENTIAL: contains unmitigated attack surface. Do not commit or share broadly."
    )
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No endpoints classified. (Check rule-pack coverage for this stack.)")
    else:
        lines.extend(_render_rows(result, color=color))

    lines.append("")
    lines.extend(_render_summary(result, color=color))
    if result.errors:
        lines.append("")
        lines.append(_bold(f"Scan warnings ({len(result.errors)}):", use_color=color))
        for err in result.errors[:20]:
            lines.append(f"  ! {err.file}: {err.message}")
        if len(result.errors) > 20:
            lines.append(f"  ... and {len(result.errors) - 20} more")
    return "\n".join(lines)


def _render_rows(result: ScanResult, *, color: bool) -> list[str]:
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
    out.append(_bold(header_line, use_color=color))
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))

    for f, row in zip(result.sorted_findings(), rows):
        state_color = _STATE_COLOR.get(f.auth_state, "")
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(row)]
        line = "  ".join(cells)
        out.append(_c(line, state_color, use_color=color) if state_color else line)
    return out


def _render_summary(result: ScanResult, *, color: bool) -> list[str]:
    counts = result.counts_by_state()
    parts = [
        f"{_c('EXPOSED', _STATE_COLOR[AuthState.EXPOSED], use_color=color)}={counts['EXPOSED']}",
        f"{_c('UNKNOWN', _STATE_COLOR[AuthState.UNKNOWN], use_color=color)}={counts['UNKNOWN']}",
        f"{_c('PROTECTED', _STATE_COLOR[AuthState.PROTECTED], use_color=color)}={counts['PROTECTED']}",
        f"{_c('PUBLIC', _STATE_COLOR[AuthState.PUBLIC], use_color=color)}={counts['PUBLIC']}",
    ]
    summary = [
        _bold("Summary", use_color=color),
        "  " + "  ".join(parts),
        f"  files scanned={result.files_scanned}  skipped={result.files_skipped}"
        f"  rulepacks={len(result.rulepacks_used)}  time={result.duration_seconds:.3f}s",
        f"  max severity={_severity_label(result.max_severity())}",
    ]
    return summary


def _severity_label(sev: Severity) -> str:
    return str(sev)
