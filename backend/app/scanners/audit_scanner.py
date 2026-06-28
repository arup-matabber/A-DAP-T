"""
Audit_Scanner — detects risky tool definitions that lack nearby audit-logging logic.

For each Tool Permission Risk finding produced by the Tool_Scanner, this module
searches a ±15-line window around the finding's line for any of the defined
audit keywords (case-insensitive).  If none is found, an "Auditability Risk"
finding is produced with a downgraded severity relative to the triggering tool:

    Critical tool → High audit risk
    High tool     → Medium audit risk

Exposed interface:
    run(tool_findings: list[Finding], files: dict[str, str]) -> list[Finding]

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6
"""

from __future__ import annotations

import re

from app.scanners.secret_scanner import Finding


# ---------------------------------------------------------------------------
# Configuration (Requirement 9.2)
# ---------------------------------------------------------------------------

# Window size: search this many lines above AND below the finding's line number
WINDOW_SIZE: int = 15

# Audit keywords — matched case-insensitively anywhere in the line text
AUDIT_KEYWORDS: list[str] = [
    "audit_log",
    "log_event",
    "trace_id",
    "tool_call_id",
    "logger",
    "event_log",
    "firebase_audit",
    "firestore_audit",
    "log_to_firestore",
    "log_to_db",
    "cloud_logging",
]

# Pre-compiled regex that matches any audit keyword (case-insensitive)
_AUDIT_RE = re.compile(
    "|".join(re.escape(kw) for kw in AUDIT_KEYWORDS),
    re.IGNORECASE,
)

# Severity downgrade mapping (Requirement 9.3)
_SEVERITY_DOWNGRADE: dict[str, str] = {
    "Critical": "High",
    "High": "Medium",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_audit_in_window(lines: list[str], finding_line: int) -> bool:
    """
    Return True when at least one audit keyword appears within ±WINDOW_SIZE
    lines of *finding_line* (1-based).

    Args:
        lines:        All source lines of the file (0-indexed list).
        finding_line: 1-based line number from the Finding.

    Returns:
        True if an audit keyword is found in the window, False otherwise.
    """
    # Convert to 0-based index for list access
    center = finding_line - 1
    start = max(0, center - WINDOW_SIZE)
    end = min(len(lines), center + WINDOW_SIZE + 1)  # exclusive upper bound

    for line in lines[start:end]:
        if _AUDIT_RE.search(line):
            return True
    return False


def _make_finding(tool_finding: Finding) -> Finding:
    """
    Build an Auditability Risk Finding based on the triggering tool finding.

    Severity downgrade (Requirement 9.3):
        Critical tool → High audit risk
        High tool     → Medium audit risk

    Args:
        tool_finding: The Tool Permission Risk finding that triggered this check.

    Returns:
        A new Finding with category "Auditability Risk".
    """
    severity = _SEVERITY_DOWNGRADE.get(tool_finding.severity, "Medium")

    return Finding(
        title=f"No audit logging found near '{tool_finding.title}'",
        severity=severity,
        category="Auditability Risk",
        file=tool_finding.file,
        line=tool_finding.line,
        why_it_matters=(
            "This high-impact tool can be executed by the AI agent with no audit "
            "trail.  Without a log entry, trace ID, or event record, it is "
            "impossible to reconstruct what actions were taken, detect abuse, or "
            "satisfy compliance requirements such as SOC 2 or GDPR accountability."
        ),
        suggested_fix=(
            "Add an audit-logging call immediately before or after this tool "
            "executes.  Use one of the recognised patterns — for example, call "
            "`audit_log(...)`, emit via a `logger` instance, record a `trace_id`, "
            "or emit an `event_log` entry — so that every invocation of this "
            "high-impact tool is traceable in your audit trail."
        ),
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run(tool_findings: list[Finding], files: dict[str, str]) -> list[Finding]:
    """
    Scan tool findings for missing audit-logging logic.

    For each Tool Permission Risk finding, a ±15-line window in the source file
    is searched for audit keywords.  If none are present, an Auditability Risk
    finding is produced with a downgraded severity.

    Args:
        tool_findings: Findings produced by the Tool_Scanner
                       (category == "Tool Permission Risk").
        files:         Mapping of relative file path → file text content.
                       Files not present in this mapping are silently skipped
                       (Requirement 9.6).

    Returns:
        List of Auditability Risk Finding objects (may be empty).
    """
    audit_findings: list[Finding] = []

    # Cache split lines per file to avoid re-splitting on each finding
    line_cache: dict[str, list[str]] = {}

    # Only consider Tool Permission Risk findings — ignore other categories
    for finding in (f for f in tool_findings if getattr(f, "category", "") == "Tool Permission Risk"):
        filepath = finding.file

        # Requirement 9.6 — skip gracefully if source is unavailable
        if filepath not in files:
            continue

        # Populate cache on first access for this file
        if filepath not in line_cache:
            line_cache[filepath] = files[filepath].splitlines()

        lines = line_cache[filepath]

        # Requirement 9.2 — search the ±15-line window
        if not _has_audit_in_window(lines, finding.line):
            # Requirement 9.3 — produce Auditability Risk finding with downgraded severity
            audit_findings.append(_make_finding(finding))
        # Requirement 9.4 — if keyword found, produce nothing

    return audit_findings
