from __future__ import annotations

import os
import re

from app.scanners.secret_scanner import Finding


RISKY_TOOL_KEYWORDS = [
    "refund",
    "payment",
    "delete",
    "admin",
    "execute",
    "shell",
    "run_command",
    "write_file",
    "read_file",
    "send_email",
    "database",
    "query_database",
    "update_user",
    "fetch_url",
    "http_request",
]

FRAMEWORK_PATTERNS = [
    ("LangChain", re.compile(r"(@tool|StructuredTool|Tool\(|DynamicTool|bind_tools|tools\s*=)", re.IGNORECASE)),
    ("LangGraph", re.compile(r"(StateGraph|add_node|add_conditional_edges|ToolNode)", re.IGNORECASE)),
    ("CrewAI", re.compile(r"(crewai|Agent\(|Task\(|Crew\(|BaseTool)", re.IGNORECASE)),
    ("OpenAI tools", re.compile(r"(tool_calls|function_call|\"type\"\s*:\s*\"function\"|tools\s*=|tools\s*:)", re.IGNORECASE)),
]

APPROVAL_HINTS = [
    "require_approval",
    "requires_approval",
    "approval_required",
    "human_approval",
    "human_review",
    "manual_review",
    "confirm_action",
    "confirm_before_execute",
    "needs_review",
    "supervisor_approval",
]


def _normalise(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _risk_keyword_in_line(line: str) -> str | None:
    normalised_line = _normalise(line)
    for keyword in RISKY_TOOL_KEYWORDS:
        if _normalise(keyword) in normalised_line:
            return keyword
    return None


def _framework_for_line(line: str) -> str | None:
    for name, pattern in FRAMEWORK_PATTERNS:
        if pattern.search(line):
            return name
    return None


def _has_approval_nearby(lines: list[str], line_number: int, window: int = 12) -> bool:
    start = max(0, line_number - 1 - window)
    end = min(len(lines), line_number + window)
    nearby = "\n".join(lines[start:end]).lower()
    return any(hint in nearby for hint in APPROVAL_HINTS)


def _severity_for_keyword(keyword: str) -> str:
    if keyword in {"refund", "payment", "delete", "admin", "execute", "shell", "run_command", "write_file"}:
        return "High"
    return "Medium"


def _scan_file(filepath: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        framework = _framework_for_line(line)
        if not framework:
            continue

        keyword = _risk_keyword_in_line(line)
        if not keyword:
            continue

        if _has_approval_nearby(lines, lineno):
            continue

        findings.append(Finding(
            title=f"Risky agent tool registration detected in {framework}",
            severity=_severity_for_keyword(keyword),
            category="Tool Permission Risk",
            file=filepath,
            line=lineno,
            why_it_matters=(
                f"This file appears to register a '{keyword}' capability through {framework}. "
                "When high-impact functions are exposed as agent tools, the agent may be able "
                "to trigger external actions, data changes, or sensitive reads through normal tool calling."
            ),
            suggested_fix=(
                "Keep the tool registered only if it is required, scope its inputs tightly, "
                "and route high-impact calls through an explicit approval gate before execution."
            ),
        ))

    return findings


def run(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    for filepath, text in files.items():
        _, ext = os.path.splitext(filepath.lower())
        if ext not in {".py", ".js", ".jsx", ".ts", ".tsx"}:
            continue
        findings.extend(_scan_file(filepath, text))

    return findings
