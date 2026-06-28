"""
Approval_Scanner — detects risky tool definitions that lack nearby human-approval logic.

For each Tool Permission Risk finding produced by the Tool_Scanner, this module
searches a ±10-line window around the finding's line for any of the defined
approval keywords (case-insensitive).  If none is found, a "Human Approval Risk"
finding is produced inheriting the severity of the triggering tool finding.

Exposed interface:
    run(tool_findings: list[Finding], files: dict[str, str]) -> list[Finding]

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""

from __future__ import annotations

import re

from app.scanners.secret_scanner import Finding


# ---------------------------------------------------------------------------
# Configuration (Requirement 8.2)
# ---------------------------------------------------------------------------

# Window size: search this many lines above AND below the finding's line number
WINDOW_SIZE: int = 10

# Approval keywords — matched case-insensitively anywhere in the line text
APPROVAL_KEYWORDS: list[str] = [
    "require_approval",
    "requires_approval",
    "approval_required",
    "human_approval",
    "human_review",
    "manual_review",
    "confirm_action",
    "confirm_before_execute",
    "approved_by",
    "approval_status",
    "approval_gate",
    "needs_review",
    "approve_before_execute",
    "supervisor_approval",
    "verify_firebase_token",
    "check_auth_status",
    "is_admin_check",
]

# Pre-compiled regex that matches any approval keyword (case-insensitive)
_APPROVAL_RE = re.compile(
    "|".join(re.escape(kw) for kw in APPROVAL_KEYWORDS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_approval_in_window(lines: list[str], finding_line: int) -> bool:
    """
    Return True when at least one approval keyword appears within ±WINDOW_SIZE
    lines of *finding_line* (1-based).

    Args:
        lines:        All source lines of the file (0-indexed list).
        finding_line: 1-based line number from the Finding.

    Returns:
        True if an approval keyword is found in the window, False otherwise.
    """
    # Convert to 0-based index for list access
    center = finding_line - 1
    start = max(0, center - WINDOW_SIZE)
    end = min(len(lines), center + WINDOW_SIZE + 1)  # exclusive upper bound

    for line in lines[start:end]:
        if _APPROVAL_RE.search(line):
            return True
    return False


def _make_finding(tool_finding: Finding) -> Finding:
    """
    Build a Human Approval Risk Finding based on the triggering tool finding.

    Severity mapping (Requirement 8.3):
        Critical tool → Critical approval risk
        High tool     → High approval risk

    Args:
        tool_finding: The Tool Permission Risk finding that triggered this check.

    Returns:
        A new Finding with category "Human Approval Risk".
    """
    severity = tool_finding.severity  # inherit directly (Critical or High)

    return Finding(
        title=f"No human approval gate found near '{tool_finding.title}'",
        severity=severity,
        category="Human Approval Risk",
        file=tool_finding.file,
        line=tool_finding.line,
        why_it_matters=(
            "This high-impact tool can be invoked by the AI agent without any "
            "human confirmation step.  If the agent is manipulated or makes an "
            "incorrect decision, the action (e.g. a financial transaction, data "
            "deletion, or external communication) will execute automatically with "
            "no opportunity for a human to intervene."
        ),
        suggested_fix=(
            "Add an explicit human-approval checkpoint before this tool executes. "
            "Use one of the recognised approval patterns — for example, wrap the "
            "call with a guard that sets/checks `approval_required`, invokes "
            "`requires_approval()`, or routes through an `approval_gate` — so that "
            "a human must confirm the action before it proceeds."
        ),
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run(tool_findings: list[Finding], files: dict[str, str]) -> list[Finding]:
    """
    Scan tool findings for missing human-approval logic.

    For each Tool Permission Risk finding, a ±10-line window in the source file
    is searched for approval keywords.  If none are present, a Human Approval
    Risk finding is produced.

    Args:
        tool_findings: Findings produced by the Tool_Scanner
                       (category == "Tool Permission Risk").
        files:         Mapping of relative file path → file text content.
                       Files not present in this mapping are silently skipped
                       (Requirement 8.6).

    Returns:
        List of Human Approval Risk Finding objects (may be empty).
    """
    approval_findings: list[Finding] = []

    # Cache split lines per file to avoid re-splitting on each finding
    line_cache: dict[str, list[str]] = {}

    # Only consider Tool Permission Risk findings — ignore other categories
    for finding in (f for f in tool_findings if getattr(f, "category", "") == "Tool Permission Risk"):
        filepath = finding.file

        # Requirement 8.6 — skip gracefully if source is unavailable
        if filepath not in files:
            continue

        # Populate cache on first access for this file
        if filepath not in line_cache:
            line_cache[filepath] = files[filepath].splitlines()

        lines = line_cache[filepath]

        # Requirement 8.2 — search the ±10-line window
        if not _has_approval_in_window(lines, finding.line):
            # Requirement 8.3 — produce Human Approval Risk finding
            approval_findings.append(_make_finding(finding))
        # Requirement 8.4 — if keyword found, produce nothing

    return approval_findings
