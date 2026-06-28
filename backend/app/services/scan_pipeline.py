from __future__ import annotations

import os

import app.scanners.approval_scanner as approval_scanner
import app.scanners.audit_scanner as audit_scanner
import app.scanners.framework_scanner as framework_scanner
import app.scanners.secret_scanner as secret_scanner
import app.scanners.tool_scanner as tool_scanner
from app.ai.ai_enrichment import enrich_scan_result_with_ai
from app.attack_simulator.simulator import build_attack_simulations
from app.deployment_gate.gate_policy import build_deployment_gate
from app.graph import build_upload_graph
from app.patches.patch_generator import build_patch_previews
from app.risk.scoring import (
    CATEGORY_TO_SCHEMA_KEY,
    compute_category_score,
    compute_overall_risk,
    compute_safety_score,
    compute_status,
    compute_summary,
)
from app.scanners.secret_scanner import Finding
from app.utils.file_utils import get_scannable_files, read_file_text


RISK_CATEGORIES = [
    "Prompt Injection Risk",
    "Secret Exposure Risk",
    "Tool Permission Risk",
    "Human Approval Risk",
    "Data Exposure Risk",
    "Auditability Risk",
]


def load_project_files(project_dir: str) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in get_scannable_files(project_dir):
        rel_path = os.path.relpath(path, project_dir).replace("\\", "/")
        files[rel_path] = read_file_text(path)
    return files


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []

    for finding in findings:
        key = (finding.category, finding.file, finding.line, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return unique


def run_scanners(files: dict[str, str]) -> list[Finding]:
    secret_findings = secret_scanner.run(files)
    tool_findings = tool_scanner.run(files)
    framework_findings = framework_scanner.run(files)

    tool_like_findings = tool_findings + framework_findings
    approval_findings = approval_scanner.run(tool_like_findings, files)
    audit_findings = audit_scanner.run(tool_like_findings, files)

    return _dedupe_findings(
        secret_findings
        + tool_findings
        + framework_findings
        + approval_findings
        + audit_findings
    )


def _category_id(category: str) -> str:
    return (
        category.lower()
        .replace(" risk", "")
        .replace(" ", "_")
        .replace("/", "_")
    )


def _evidence_for_finding(finding: Finding, files: dict[str, str]) -> str:
    text = files.get(finding.file, "")
    if not text:
        return ""

    lines = text.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return ""

    return lines[finding.line - 1].strip()[:220]


def serialize_findings(findings: list[Finding], files: dict[str, str] | None = None) -> list[dict]:
    counters: dict[str, int] = {}
    serialized: list[dict] = []
    files = files or {}

    for finding in findings:
        key = _category_id(finding.category)
        counters[key] = counters.get(key, 0) + 1
        serialized.append(
            {
                "id": f"{key}_{counters[key]:03d}",
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "file": finding.file,
                "line": finding.line,
                "why_it_matters": finding.why_it_matters,
                "suggested_fix": finding.suggested_fix,
                "description": finding.why_it_matters,
                "evidence": _evidence_for_finding(finding, files),
            }
        )

    return serialized


def _serialize_graph(graph: dict) -> dict:
    if not graph or not isinstance(graph, dict):
        return graph

    def to_dict(obj):
        if hasattr(obj, "dict"):
            return obj.dict()
        if isinstance(obj, dict):
            return obj
        return obj

    return {
        "nodes": [to_dict(node) for node in graph.get("nodes", [])],
        "edges": [to_dict(edge) for edge in graph.get("edges", [])],
    }


def build_category_scores(findings: list[Finding]) -> dict[str, int]:
    category_scores: dict[str, int] = {}
    for category in RISK_CATEGORIES:
        schema_key = CATEGORY_TO_SCHEMA_KEY[category]
        category_scores[schema_key] = compute_category_score(findings, category)
    return category_scores


def build_remediation_checklist(findings: list[Finding]) -> list[str]:
    checklist: list[str] = []

    def add_once(item: str) -> None:
        if item not in checklist:
            checklist.append(item)

    for finding in findings:
        if finding.severity in {"Critical", "High"}:
            add_once(finding.suggested_fix)

    if any(f.category == "Tool Permission Risk" for f in findings):
        add_once("Review all tools exposed to the agent and scope them to the minimum required permissions")
    if any(f.category == "Human Approval Risk" for f in findings):
        add_once("Add approval gates before refund, delete, email, database write, and filesystem actions")
    if any(f.category == "Auditability Risk" for f in findings):
        add_once("Log every tool call with timestamp, tool name, redacted arguments, and request/session ID")
    if any(f.category == "Secret Exposure Risk" for f in findings):
        add_once("Move secrets to environment variables or a secret manager and rotate exposed values")

    if not checklist:
        return [
            "Keep adversarial prompt tests in the release checklist",
            "Review tool permissions whenever new tools are added",
            "Monitor audit logs for abnormal tool use",
        ]

    return checklist[:8]


def build_attack_replay(findings: list[Finding]) -> list[str]:
    replay = ["User submits a malicious or unexpected prompt"]

    if any(f.category == "Prompt Injection Risk" for f in findings):
        replay.append("Prompt handling allows attacker-controlled text near agent instructions")
    else:
        replay.append("Prompt injection checks did not find direct prompt-construction issues")

    if any(f.category == "Tool Permission Risk" for f in findings):
        replay.append("Agent has access to at least one high-impact tool")

    if any(f.category == "Human Approval Risk" for f in findings):
        replay.append("Risky tool path has no nearby human approval gate")
    else:
        replay.append("Approval-related patterns were found near risky tool paths or no risky tool path was detected")

    if any(f.category == "Auditability Risk" for f in findings):
        replay.append("Tool execution path lacks clear audit logging")

    replay.append("A-DAP-T flags the deployment risk before release")
    return replay


def attach_v2_report_artifacts(result: dict) -> dict:
    """Attach V2 proof, patch, and gate fields derived from deterministic findings."""
    updated = dict(result)
    findings = updated.get("findings") or []
    updated["attack_simulations"] = build_attack_simulations(findings)
    updated["patches"] = build_patch_previews(findings)
    updated["deployment_gate"] = build_deployment_gate(updated)
    updated.setdefault("score_delta", None)
    return updated


def build_scan_result(
    project_dir: str,
    project_name: str,
    scan_type: str,
    extra_metadata: dict | None = None,
    enrich: bool = True,
) -> dict:
    files = load_project_files(project_dir)
    findings = run_scanners(files)
    category_scores = build_category_scores(findings)
    overall_risk = compute_overall_risk(category_scores)
    safety_score = compute_safety_score(overall_risk)

    result = {
        "project_name": project_name,
        "scan_type": scan_type,
        "safety_score": safety_score,
        "status": compute_status(safety_score),
        "summary": compute_summary(findings),
        "category_scores": category_scores,
        "findings": serialize_findings(findings, files),
        "graph": _serialize_graph(build_upload_graph(findings)),
        "attack_replay": build_attack_replay(findings),
        "remediation_checklist": build_remediation_checklist(findings),
    }

    result = attach_v2_report_artifacts(result)

    if extra_metadata:
        result.update(extra_metadata)

    if not enrich:
        return result

    return enrich_scan_result_with_ai(result)
