"""
Tool_Scanner — detects risky function/tool definitions and data-exposure patterns.

Exposed interface:
    run(files: dict[str, str]) -> list[Finding]

Requirements: 7.1–7.6, 17.1–17.4
"""

from __future__ import annotations

import json
import os
import re

from app.scanners.secret_scanner import Finding


# ---------------------------------------------------------------------------
# Tool Permission Risk — keyword tiers (Requirements 7.2, 7.3)
# ---------------------------------------------------------------------------

CRITICAL_TOOL_KEYWORDS: list[str] = [
    "refund",
    "send_refund",
    "issue_refund",
    "payment",
    "delete",
    "delete_user",
    "admin",
    "execute",
    "execute_code",
    "shell",
    "run_shell",
    "run_command",
    "write_file",
    "write_database",
    "write_db",
    "drop_table",
    "firestore_delete",
    "firebase_admin",
    "delete_collection",
    "delete_document",
]

HIGH_TOOL_KEYWORDS: list[str] = [
    "send_email",
    "send_message",
    "send_slack",
    "customer",
    "database",
    "query_database",
    "read_file",
    "fetch_url",
    "http_request",
    "update_user",
    "update_database",
    "crm",
    "firestore_update",
    "firestore_set",
    "firebase_write",
    "update_document",
]

# ---------------------------------------------------------------------------
# Data Exposure Risk — data-access and masking keywords (Requirements 17.1, 17.2)
# ---------------------------------------------------------------------------

DATA_ACCESS_KEYWORDS: list[str] = [
    "get_customer",
    "read_internal",
    "get_user_data",
    "fetch_record",
    "get_record",
    "firestore_get",
    "firebase_read",
    "get_document",
    "list_documents",
]

MASKING_KEYWORDS: list[str] = [
    "mask_",
    "redact_",
    "anonymize",
    "sanitize",
]

# Sensitive JSON top-level / nested keys (Requirement 17.3)
SENSITIVE_JSON_KEYS: list[str] = [
    "email",
    "phone",
    "ssn",
    "credit_card",
    "password",
]

# Window size for data-exposure masking check (Requirement 17.2)
DATA_EXPOSURE_WINDOW = 10
# Mitigation keywords — presence reduces or suppresses tool findings
APPROVAL_KEYWORDS_MITIGATIONS = [
    "request_human_review",
    "require_approval",
    "requires_approval",
    "approval_required",
    "approval_gate",
    "human_approval",
    "human_review",
    "manual_review",
    "confirm_action",
    "confirm_before_execute",
    "needs_review",
    "supervisor_approval",
]

AUDIT_KEYWORDS_MITIGATIONS = [
    "audit_log",
    "log_event",
    "trace_id",
    "tool_call_id",
    "logger",
]

WRAPPER_KEYWORDS_MITIGATIONS = [
    "safe_",
    "with_approval",
    "_with_approval",
    "safe_refund",
    "refund_with_approval",
]

_MITIGATION_RE = re.compile(
    "|".join(re.escape(kw) for kw in (
        APPROVAL_KEYWORDS_MITIGATIONS + AUDIT_KEYWORDS_MITIGATIONS + WRAPPER_KEYWORDS_MITIGATIONS
    )),
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Function definition patterns (Requirement 7.4)
# ---------------------------------------------------------------------------

# Matches:  def function_name( or async def function_name(
_PY_FUNC_RE = re.compile(r"(?:async\s+)?def\s+(\w+)\s*\(", re.IGNORECASE)

# Matches:  function function_name( or async function function_name(
_JS_FUNC_RE = re.compile(r"(?:async\s+)?function\s+(\w+)\s*\(", re.IGNORECASE)

# Matches: const sendEmail = (...) => or export const sendEmail = async (...) =>
_JS_ARROW_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_func_pattern(ext: str) -> re.Pattern | None:
    """Return the appropriate function-definition regex for the given file extension."""
    if ext == ".py":
        return _PY_FUNC_RE
    if ext in {".js", ".jsx", ".ts", ".tsx"}:
        return _JS_FUNC_RE
    return None


def _normalize_identifier(value: str) -> str:
    """Make snake_case keywords and camelCase names comparable."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _classify_tool_keyword(func_name: str) -> tuple[str, str] | None:
    """
    Check whether *func_name* contains a critical- or high-tier tool keyword.

    This intentionally normalizes names, so sendEmail matches send_email and
    issueRefund matches issue_refund. Real agent repos mix naming styles.
    """
    normalized_name = _normalize_identifier(func_name)
    for kw in CRITICAL_TOOL_KEYWORDS:
        if _normalize_identifier(kw) in normalized_name:
            return "Critical", kw
    for kw in HIGH_TOOL_KEYWORDS:
        if _normalize_identifier(kw) in normalized_name:
            return "High", kw
    return None


def _classify_data_access_keyword(func_name: str) -> str | None:
    """Return the matched data-access keyword if func_name contains one, else None."""
    lower_name = func_name.lower()
    for kw in DATA_ACCESS_KEYWORDS:
        if kw in lower_name:
            return kw
    return None


def _has_masking_in_window(lines: list[str], line_number: int) -> bool:
    """
    Return True if any masking keyword appears within ±DATA_EXPOSURE_WINDOW lines
    of *line_number* (1-based) in *lines*.
    """
    start = max(0, line_number - 1 - DATA_EXPOSURE_WINDOW)
    end = min(len(lines), line_number + DATA_EXPOSURE_WINDOW)
    window_text = " ".join(lines[start:end]).lower()
    return any(mk in window_text for mk in MASKING_KEYWORDS)


def _has_mitigation_in_window(lines: list[str], line_number: int, window: int = 15) -> dict:
    """
    Search for mitigation keywords within a window around *line_number*.

    Returns a dict with boolean flags: {'approval': bool, 'audit': bool, 'wrapper': bool}
    """
    start = max(0, line_number - 1 - window)
    end = min(len(lines), line_number + window)
    window_text = "\n".join(lines[start:end]).lower()

    # Use word-boundary regex for approval/audit to avoid matching inside identifiers
    approval = any(re.search(r"\b" + re.escape(kw.lower()) + r"\b", window_text) for kw in APPROVAL_KEYWORDS_MITIGATIONS)
    audit = any(re.search(r"\b" + re.escape(kw.lower()) + r"\b", window_text) for kw in AUDIT_KEYWORDS_MITIGATIONS)
    # Wrapper keywords are often prefixes (e.g. safe_refund) so substring match is appropriate
    wrapper = any(kw.lower() in window_text for kw in WRAPPER_KEYWORDS_MITIGATIONS)

    return {"approval": approval, "audit": audit, "wrapper": wrapper}


def _collect_json_keys(obj: object, found: set[str]) -> None:
    """Recursively collect all dict keys from a parsed JSON object into *found*."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            found.add(str(key).lower())
            _collect_json_keys(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _collect_json_keys(item, found)


def _scan_code_file(filepath: str, text: str, ext: str) -> list[Finding]:
    """
    Scan a single Python / JS / TS source file for:
      - Risky tool function definitions  → Tool Permission Risk
      - Data-access functions w/o masking → Data Exposure Risk
    """
    findings: list[Finding] = []
    func_re = _get_func_pattern(ext)
    if func_re is None:
        return findings

    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        match = func_re.search(line)
        if not match and ext in {".js", ".jsx", ".ts", ".tsx"}:
            match = _JS_ARROW_FUNC_RE.search(line)
        if not match:
            continue

        func_name = match.group(1)

        # ── Tool Permission Risk ──────────────────────────────────────────
        result = _classify_tool_keyword(func_name)
        if result is not None:
            severity, matched_kw = result

            # Check for nearby mitigations (approval, audit logging, wrappers)
            mitigations = _has_mitigation_in_window(lines, lineno)

            # If strong mitigations exist (approval AND audit OR explicit safe wrapper), suppress the finding
            if (mitigations.get("approval") and mitigations.get("audit")) or mitigations.get("wrapper"):
                # don't report a Tool Permission finding — mitigations present
                pass
            else:
                # If some mitigations exist, reduce severity substantially
                if mitigations.get("approval") or mitigations.get("audit"):
                    new_severity = "Medium" if severity == "Critical" else "Low"
                    why = (
                        f"The function '{func_name}' performs or exposes a '{matched_kw}' operation. "
                        "A partial mitigation was detected nearby, so the effective risk is reduced. "
                    )
                    suggested = (
                        f"Ensure a robust approval AND audit trail around '{func_name}', or move the action behind "
                        "a dedicated safe wrapper to eliminate residual risk."
                    )
                else:
                    new_severity = severity
                    why = (
                        f"The function '{func_name}' performs or exposes a '{matched_kw}' operation. If this function is registered "
                        "as an AI-agent tool, the agent can autonomously invoke a high-impact action without additional constraints."
                    )
                    suggested = (
                        f"Add a human-approval gate or confirmation step before executing '{func_name}'. Scope the function's permissions "
                        "to the minimum required and log every invocation for audit."
                    )

                findings.append(Finding(
                    title=f"Risky function '{func_name}' detected",
                    severity=new_severity,
                    category="Tool Permission Risk",
                    file=filepath,
                    line=lineno,
                    why_it_matters=why,
                    suggested_fix=suggested,
                ))

        # ── Data Exposure Risk ────────────────────────────────────────────
        da_kw = _classify_data_access_keyword(func_name)
        if da_kw is not None:
            if not _has_masking_in_window(lines, lineno):
                findings.append(Finding(
                    title=f"Data-access function '{func_name}' without masking",
                    severity="High",
                    category="Data Exposure Risk",
                    file=filepath,
                    line=lineno,
                    why_it_matters=(
                        f"The function '{func_name}' accesses sensitive customer "
                        "data but no masking, redaction, or anonymization logic "
                        "was detected within 10 lines of its definition. Returning "
                        "raw PII to the agent increases the risk of data leakage."
                    ),
                    suggested_fix=(
                        "Apply a masking or redaction helper (e.g. `mask_pii()`, "
                        "`redact_fields()`) to sensitive fields before returning "
                        f"data from '{func_name}'. Store only what is necessary."
                    ),
                ))

    return findings


def _scan_json_file(filepath: str, text: str) -> list[Finding]:
    """
    Scan a JSON file for sensitive top-level or nested keys (Requirement 17.3).
    Returns at most one Finding per file.
    """
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    found_keys: set[str] = set()
    _collect_json_keys(obj, found_keys)

    matched = [k for k in SENSITIVE_JSON_KEYS if k in found_keys]
    if not matched:
        return []

    matched_display = ", ".join(f"'{k}'" for k in matched)
    return [Finding(
        title=f"Sensitive data keys detected in JSON file",
        severity="Medium",
        category="Data Exposure Risk",
        file=filepath,
        line=1,
        why_it_matters=(
            f"The JSON file contains key(s) {matched_display} that typically "
            "hold personally identifiable information (PII). If this file is "
            "committed to version control or served without access controls, "
            "sensitive customer data may be exposed."
        ),
        suggested_fix=(
            "Remove real PII from committed JSON files and replace with "
            "anonymised sample data. For runtime data, ensure the file is "
            "excluded from version control and access is restricted to "
            "authorised services only."
        ),
    )]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run(files: dict[str, str]) -> list[Finding]:
    """
    Scan all provided files for risky tool definitions and data-exposure patterns.

    Args:
        files: Mapping of relative file path → file text content.

    Returns:
        List of Finding objects (may be empty).
        These findings are also used as input by Approval_Scanner and Audit_Scanner.
    """
    findings: list[Finding] = []

    for filepath, text in files.items():
        _, ext = os.path.splitext(filepath.lower())

        if ext in {".py", ".js", ".jsx", ".ts", ".tsx"}:
            findings.extend(_scan_code_file(filepath, text, ext))
        elif ext == ".json":
            findings.extend(_scan_json_file(filepath, text))

    return findings
