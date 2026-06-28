from __future__ import annotations

from typing import Any

SECURITY_ASSISTANT_SYSTEM_INSTRUCTION = """
You are DAP, the report-aware assistant for A-DAP-T.

You only answer questions about:
- the current A-DAP-T scan report
- findings, safety score, risk categories, and remediation
- attack simulations, patch previews, and deployment gate decisions
- AI-agent deployment risks such as prompt injection, exposed secrets, unsafe tools,
  missing approval gates, data exposure, and auditability

Guardrails:
- Answer only from the provided scan_result.
- Do not invent vulnerabilities, files, patches, attack paths, or deployment blockers.
- If the question is outside A-DAP-T/security/remediation, refuse with:
  "I can only assist with A-DAP-T security analysis, findings, and safety score improvement."
- Keep normal answers under 120 words.
- Use at most 5 bullets.
- Be concrete and developer-friendly.
"""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _limit(items: list[Any], limit: int) -> list[Any]:
    return items[:limit] if isinstance(items, list) else []


def _finding_ref(item: dict, fallback: str) -> str:
    return _text(item.get("id") or item.get("finding_id") or fallback)


def _format_findings(scan_result: dict) -> str:
    findings = scan_result.get("findings") or []
    lines: list[str] = []
    for idx, finding in enumerate(_limit(findings, 12), start=1):
        finding_id = _finding_ref(finding, f"finding_{idx:03d}")
        title = _text(finding.get("title") or "Untitled finding")
        severity = _text(finding.get("severity") or "Unknown")
        category = _text(finding.get("category") or "Unknown")
        file_path = _text(finding.get("file") or "unknown file")
        line = finding.get("line")
        fix = _text(finding.get("suggested_fix") or finding.get("fix") or "No fix provided")
        evidence = _text(finding.get("evidence"))[:160]
        location = f"{file_path}:{line}" if line else file_path
        evidence_suffix = f" | Evidence: {evidence}" if evidence else ""
        lines.append(
            f"{finding_id}: [{severity}] {title} | {category} | {location} | Fix: {fix}{evidence_suffix}"
        )
    return "\n".join(lines) if lines else "No findings were provided."


def _format_attack_simulations(scan_result: dict) -> str:
    simulations = scan_result.get("attack_simulations") or []
    lines: list[str] = []
    for idx, item in enumerate(_limit(simulations, 8), start=1):
        finding_id = _finding_ref(item, f"simulation_{idx:03d}")
        title = _text(item.get("title") or "Attack simulation")
        risk = _text(item.get("risk_level") or "unknown")
        malicious = _text(item.get("malicious_input"))[:180]
        impact = _text(item.get("impact"))[:180]
        guardrail = _text(item.get("guardrail") or item.get("required_fix"))[:180]
        signal = _text(item.get("detection_signal"))[:160]
        lines.append(
            f"{finding_id}: [{risk}] {title} | Prompt/trigger: {malicious} | Impact: {impact} | Guardrail: {guardrail} | Detection signal: {signal}"
        )
    return "\n".join(lines) if lines else "No attack simulations were generated."


def _format_patches(scan_result: dict) -> str:
    patches = scan_result.get("patches") or []
    lines: list[str] = []
    for idx, item in enumerate(_limit(patches, 8), start=1):
        finding_id = _finding_ref(item, f"patch_{idx:03d}")
        title = _text(item.get("title") or "Patch preview")
        patch_type = _text(item.get("patch_type") or "unknown")
        file_path = _text(item.get("file") or "unknown file")
        filename = _text(item.get("patch_filename") or "patch.diff")
        confidence = _text(item.get("confidence") or "medium")
        explanation = _text(item.get("explanation"))[:180]
        effort = _text(item.get("estimated_effort") or "medium")
        reduction = _text(item.get("risk_reduction"))[:160]
        lines.append(
            f"{finding_id}: {title} | Type: {patch_type} | File: {file_path} | Patch file: {filename} | Confidence: {confidence} | Effort: {effort} | Risk reduction: {reduction} | {explanation}"
        )
    return "\n".join(lines) if lines else "No patch previews were generated."


def _format_deployment_gate(scan_result: dict) -> str:
    gate = scan_result.get("deployment_gate") or {}
    if not isinstance(gate, dict) or not gate:
        return "No deployment gate decision was generated."

    decision = _text(gate.get("decision") or "UNKNOWN")
    summary = _text(gate.get("summary"))
    action = _text(gate.get("required_action"))
    blockers = gate.get("blockers") or []
    blockers_text = "; ".join(_text(item) for item in blockers[:5]) if isinstance(blockers, list) else ""
    workflow = _text(gate.get("workflow_filename") or "adapt-agent-safety-gate.yml")
    policy = _text(gate.get("policy_filename") or "adapt-policy.json")
    badge = _text(gate.get("decision_badge"))
    next_actions = gate.get("next_actions") or []
    next_text = "; ".join(_text(item) for item in next_actions[:4]) if isinstance(next_actions, list) else ""

    return (
        f"Decision: {decision} ({badge})\n"
        f"Summary: {summary}\n"
        f"Required action: {action}\n"
        f"Next actions: {next_text or 'None'}\n"
        f"Blockers: {blockers_text or 'None'}\n"
        f"Generated files: {workflow}, {policy}"
    )


def build_assistant_user_prompt(question: str, scan_result: dict) -> str:
    safety_score = scan_result.get("safety_score", "Unknown")
    status = scan_result.get("status", "Unknown")
    category_scores = scan_result.get("category_scores", {})

    return f"""
Current scan context:
Project: {scan_result.get('project_name', 'Current Project')}
Scan type: {scan_result.get('scan_type', 'Standard')}
Safety score: {safety_score}/100
Risk status: {status}
Category scores: {category_scores}

Findings:
{_format_findings(scan_result)}

Attack simulations / Prove Mode:
{_format_attack_simulations(scan_result)}

Patch previews:
{_format_patches(scan_result)}

Deployment gate:
{_format_deployment_gate(scan_result)}

User question:
{question}
"""
