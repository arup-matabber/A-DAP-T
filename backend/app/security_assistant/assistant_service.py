from __future__ import annotations

import logging
import re
from typing import Any

from app.ai.gemini_service import GeminiService
from app.security_assistant.assistant_prompt import (
    SECURITY_ASSISTANT_SYSTEM_INSTRUCTION,
    build_assistant_user_prompt,
)

logger = logging.getLogger("fastapi")

REFUSAL_TEXT = "I can only assist with A-DAP-T security analysis, findings, and safety score improvement."

ALLOWED_KEYWORDS = [
    "score", "risk", "vulnerability", "finding", "secret", "key", "token", "leak",
    "prompt", "injection", "tool", "permission", "approval", "gate", "human",
    "audit", "log", "trace", "exposure", "data", "pii", "mask", "remediation",
    "fix", "secure", "patch", "agent", "vulnerable", "config", "jwt", "report",
    "category", "dashboard", "deploy", "deployment", "block", "allow", "review",
    "attack", "simulate", "prove", "proof", "guardrail", "workflow", "github action",
    "ci", "cd", "yml", "yaml", "policy",
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _clean_answer(text: str, max_words: int = 120) -> str:
    text = str(text or "")
    text = text.replace("**", "").replace("`", "")
    text = re.sub(r"^\s*#+\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    words = text.split()
    if len(words) <= max_words:
        return text

    short = " ".join(words[:max_words]).rstrip(".,;:")
    return short if short.endswith((".", "!", "?")) else short + "."


def _findings(scan_result: dict) -> list[dict]:
    items = scan_result.get("findings") or []
    return items if isinstance(items, list) else []


def _simulations(scan_result: dict) -> list[dict]:
    items = scan_result.get("attack_simulations") or []
    return items if isinstance(items, list) else []


def _patches(scan_result: dict) -> list[dict]:
    items = scan_result.get("patches") or []
    return items if isinstance(items, list) else []


def _gate(scan_result: dict) -> dict:
    gate = scan_result.get("deployment_gate") or {}
    return gate if isinstance(gate, dict) else {}


def _sorted_findings(scan_result: dict) -> list[dict]:
    return sorted(
        _findings(scan_result),
        key=lambda item: SEVERITY_RANK.get(_lower(item.get("severity")), 9),
    )


def _linked_patch(scan_result: dict, finding_id: str) -> dict | None:
    for patch in _patches(scan_result):
        if _text(patch.get("finding_id")) == finding_id:
            return patch
    return None


def _linked_simulation(scan_result: dict, finding_id: str) -> dict | None:
    for simulation in _simulations(scan_result):
        if _text(simulation.get("finding_id")) == finding_id:
            return simulation
    return None


def _first_blocked_finding(scan_result: dict) -> dict | None:
    findings = _sorted_findings(scan_result)
    if not findings:
        return None

    gate = _gate(scan_result)
    blockers = " ".join(_text(item) for item in (gate.get("blockers") or [])).lower()
    for finding in findings:
        category = _lower(finding.get("category"))
        if "secret" in blockers and "secret" in category:
            return finding
        if "approval" in blockers and "approval" in category:
            return finding
        if "tool" in blockers and "tool" in category:
            return finding
        if "critical" in blockers and _lower(finding.get("severity")) == "critical":
            return finding
    return findings[0]


def _format_finding_line(finding: dict) -> str:
    title = _text(finding.get("title") or "Untitled finding")
    severity = _text(finding.get("severity") or "Unknown")
    file_path = _text(finding.get("file") or "unknown file")
    line = finding.get("line")
    location = f"{file_path}:{line}" if line else file_path
    return f"[{severity}] {title} in {location}"


def _deployment_answer(scan_result: dict) -> str:
    gate = _gate(scan_result)
    if not gate:
        return "No deployment gate result is attached to this report. Re-run the scan with V2 report artifacts enabled."

    decision = _text(gate.get("decision") or "UNKNOWN")
    summary = _text(gate.get("summary"))
    action = _text(gate.get("required_action"))
    blockers = gate.get("blockers") or []
    workflow = _text(gate.get("workflow_filename") or "adapt-agent-safety-gate.yml")
    policy = _text(gate.get("policy_filename") or "adapt-policy.json")
    badge = _text(gate.get("decision_badge"))
    next_actions = gate.get("next_actions") or []

    lines = [f"Deployment gate: {decision}."]
    if badge:
        lines.append("Verdict: " + badge)
    if summary:
        lines.append(summary)
    if blockers:
        lines.append("Blockers: " + "; ".join(_text(item) for item in blockers[:4]))
    if action:
        lines.append("Required action: " + action)
    if isinstance(next_actions, list) and next_actions:
        lines.append("Next actions: " + "; ".join(_text(item) for item in next_actions[:3]))
    lines.append(f"Use {workflow} and {policy} as the CI gate artifacts.")
    return "\n".join(lines)


def _attack_answer(scan_result: dict) -> str:
    simulations = _simulations(scan_result)
    if not simulations:
        return "No attack simulation is attached to this report. I can only prove risks that A-DAP-T actually detected."

    top = simulations[0]
    title = _text(top.get("title") or "Attack simulation")
    malicious = _text(top.get("malicious_input"))
    impact = _text(top.get("impact"))
    guardrail = _text(top.get("guardrail") or top.get("required_fix"))
    signal = _text(top.get("detection_signal"))
    steps = top.get("attack_steps") or []
    step_text = "; ".join(_text(item) for item in steps[:3]) if isinstance(steps, list) else ""

    return (
        f"Most relevant proof path: {title}.\n"
        f"Malicious input: {malicious}\n"
        f"Expected impact: {impact}\n"
        f"Attack steps: {step_text}\n"
        f"Detection signal: {signal}\n"
        f"Required guardrail: {guardrail}"
    )


def _patch_answer(scan_result: dict) -> str:
    patches = _patches(scan_result)
    if not patches:
        return "No patch preview is attached to this report. Use the finding suggested fixes and re-run the scan after changes."

    patch = patches[0]
    title = _text(patch.get("title") or "Patch preview")
    filename = _text(patch.get("patch_filename") or "patch.diff")
    explanation = _text(patch.get("explanation"))
    confidence = _text(patch.get("confidence") or "medium")
    effort = _text(patch.get("estimated_effort") or "medium")
    risk_reduction = _text(patch.get("risk_reduction"))

    return (
        f"Start with patch preview: {title}.\n"
        f"Download/copy: {filename}.\n"
        f"Confidence: {confidence}; effort: {effort}.\n"
        f"Risk reduction: {risk_reduction}\n"
        f"Why: {explanation}\n"
        "Review manually before applying; A-DAP-T does not auto-modify source code."
    )


def _fix_first_answer(scan_result: dict) -> str:
    finding = _first_blocked_finding(scan_result)
    if not finding:
        return "This report has no findings. Keep normal adversarial testing and release monitoring in place."

    finding_id = _text(finding.get("id"))
    patch = _linked_patch(scan_result, finding_id)
    simulation = _linked_simulation(scan_result, finding_id)

    lines = ["Fix this first: " + _format_finding_line(finding) + "."]
    fix = _text(finding.get("suggested_fix"))
    if fix:
        lines.append("Recommended fix: " + fix)
    if simulation:
        lines.append("Why it matters: " + _text(simulation.get("impact")))
    if patch:
        filename = _text(patch.get("patch_filename") or "patch.diff")
        lines.append("Use patch preview: " + filename)
    gate = _gate(scan_result)
    if gate.get("decision") == "BLOCK":
        lines.append("This also helps clear the deployment gate blockers.")
    return "\n".join(lines)


class SecurityAssistantService:
    def __init__(self):
        self.gemini_service = GeminiService()

    def _is_obviously_unrelated(self, question: str) -> bool:
        q_lower = question.lower()
        if any(keyword in q_lower for keyword in ALLOWED_KEYWORDS):
            return False

        disallowed_indicators = [
            "ipl", "cricket", "football", "poem", "story", "dsa", "leetcode",
            "normalization", "dbms", "sql index", "weather", "recipe",
        ]
        return any(indicator in q_lower for indicator in disallowed_indicators)

    def _deterministic_answer(self, question: str, scan_result: dict) -> str:
        q = question.lower()
        if any(word in q for word in ("deploy", "deployment", "block", "allow", "ci", "workflow", "github action", "policy")):
            return _deployment_answer(scan_result)
        if any(word in q for word in ("attack", "prove", "simulate", "malicious", "exploit")):
            return _attack_answer(scan_result)
        if any(word in q for word in ("patch", "diff", "code", "fix preview", "download")):
            return _patch_answer(scan_result)
        return _fix_first_answer(scan_result)

    def ask_assistant(self, question: str, scan_result: dict) -> str:
        if self._is_obviously_unrelated(question):
            return REFUSAL_TEXT

        if not scan_result:
            return "Run or open a scan report first so I can answer from actual A-DAP-T findings."

        fallback = self._deterministic_answer(question, scan_result)

        if not self.gemini_service.is_available():
            return _clean_answer(fallback)

        try:
            response_text = self.gemini_service.generate_text(
                prompt=build_assistant_user_prompt(question, scan_result),
                system_instruction=SECURITY_ASSISTANT_SYSTEM_INSTRUCTION,
            )
            return _clean_answer(response_text) if response_text else _clean_answer(fallback)

        except Exception as exc:
            logger.error(f"Error in SecurityAssistantService: {str(exc)}")
            return _clean_answer(fallback)
