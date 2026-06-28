from __future__ import annotations

import re
from typing import Any

_SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".json": "json",
    ".txt": "text",
    ".md": "markdown",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _category(finding: dict) -> str:
    return _text(finding.get("category")).lower()


def _title(finding: dict) -> str:
    return _text(finding.get("title"))


def _finding_id(finding: dict, index: int) -> str:
    return _text(finding.get("id")) or f"finding_{index + 1:03d}"


def _file(finding: dict) -> str:
    return _text(finding.get("file")) or "project file"


def _extension(path: str) -> str:
    if "." not in path:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _language(path: str) -> str:
    return _SUPPORTED_EXTENSIONS.get(_extension(path), "text")


def _evidence(finding: dict) -> str:
    return _text(finding.get("evidence"))


def _severity(finding: dict) -> str:
    return _text(finding.get("severity") or "medium").lower()


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "patch"


def _patch_filename(finding: dict, index: int, patch_type: str) -> str:
    finding_id = _finding_id(finding, index)
    return f"{_safe_slug(finding_id)}-{_safe_slug(patch_type)}.patch"


def _line(finding: dict) -> int | None:
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _effort_for_patch(patch_type: str, confidence: str) -> str:
    if confidence == "low":
        return "medium"
    if patch_type in {"env_secret_fix", "audit_logging_addition"}:
        return "low"
    return "medium"


def _controls_for_patch(patch_type: str) -> list[str]:
    mapping = {
        "env_secret_fix": ["secret_management", "configuration_hardening"],
        "human_approval_wrapper": ["human_in_the_loop", "high_impact_action_control"],
        "audit_logging_addition": ["auditability", "incident_response"],
        "pii_masking_helper": ["data_minimization", "pii_protection"],
        "prompt_input_sanitization": ["prompt_boundary", "prompt_injection_resistance"],
        "tool_scope_guard": ["least_privilege_tools", "agent_permission_boundary"],
    }
    return mapping.get(patch_type, ["agent_deployment_safety"])


def _validation_steps(patch_type: str) -> list[str]:
    common = ["Apply manually in a branch or staging copy.", "Run the A-DAP-T scan again and compare score/finding changes."]
    specific = {
        "env_secret_fix": ["Confirm the secret is loaded from runtime configuration.", "Rotate the exposed value and verify the old value no longer works."],
        "human_approval_wrapper": ["Test that the risky action fails closed without approval.", "Verify approval metadata is recorded with the tool call."],
        "audit_logging_addition": ["Trigger the tool in staging and verify logs include user, tool, request ID, redacted arguments, and outcome."],
        "pii_masking_helper": ["Test with sample customer data and verify raw email/phone/address/token values are not returned."],
        "prompt_input_sanitization": ["Run adversarial prompt cases and verify user input is treated as data, not instructions."],
        "tool_scope_guard": ["Try an out-of-scope action and verify the tool refuses or routes to approval."],
    }
    return specific.get(patch_type, []) + common


def _risk_reduction_for_patch(patch_type: str) -> str:
    mapping = {
        "env_secret_fix": "Reduces credential leakage and post-deployment key abuse risk.",
        "human_approval_wrapper": "Reduces excessive-agency risk for high-impact actions.",
        "audit_logging_addition": "Improves incident review and traceability for agent tool calls.",
        "pii_masking_helper": "Reduces sensitive data exposure in agent responses and logs.",
        "prompt_input_sanitization": "Reduces prompt injection and instruction-confusion risk.",
        "tool_scope_guard": "Reduces broad tool access by enforcing least privilege and approval boundaries.",
    }
    return mapping.get(patch_type, "Reduces the linked deployment risk when reviewed and applied correctly.")


def _patch_base(finding: dict, index: int, *, title: str, patch_type: str, before: str, after: str, diff: str, explanation: str, confidence: str = "medium") -> dict:
    filename = _patch_filename(finding, index, patch_type)
    return {
        "finding_id": _finding_id(finding, index),
        "title": title,
        "file": _file(finding),
        "line": _line(finding),
        "language": _language(_file(finding)),
        "patch_type": patch_type,
        "patch_filename": filename,
        "copy_label": "Copy patch preview",
        "download_label": f"Download {filename}",
        "before": before,
        "after": after,
        "diff": diff,
        "explanation": explanation,
        "confidence": confidence,
        "manual_review_required": True,
        "apply_strategy": "preview_only",
        "estimated_effort": _effort_for_patch(patch_type, confidence),
        "risk_reduction": _risk_reduction_for_patch(patch_type),
        "affected_controls": _controls_for_patch(patch_type),
        "validation_steps": _validation_steps(patch_type),
        "review_notes": [
            "This is a generated patch preview, not an automatic code modification.",
            "Review surrounding code, imports, tests, and runtime configuration before applying.",
        ],
    }


def _secret_name(finding: dict) -> str:
    combined = f"{_title(finding)}\n{_evidence(finding)}".upper()
    for candidate in ("OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "JWT_SECRET", "SECRET_KEY", "API_KEY", "TOKEN"):
        if candidate in combined:
            return candidate
    var_match = re.search(r"\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))\b", combined)
    if var_match:
        return var_match.group(1)
    return "API_KEY"


def _secret_patch(finding: dict, index: int) -> dict:
    evidence = _evidence(finding) or 'API_KEY = "replace-me"'
    key_name = _secret_name(finding)
    path = _file(finding)
    lang = _language(path)

    if lang == "python":
        after = f'{key_name} = os.getenv("{key_name}")\nif not {key_name}:\n    raise RuntimeError("{key_name} is not configured")'
        diff = f"- {evidence}\n+ {key_name} = os.getenv(\"{key_name}\")\n+ if not {key_name}:\n+     raise RuntimeError(\"{key_name} is not configured\")"
        import_note = "Add `import os` at the top of the file if it is not already present."
    elif lang in {"javascript", "typescript"}:
        after = f'const {key_name} = process.env.{key_name};\nif (!{key_name}) throw new Error("{key_name} is not configured");'
        diff = f"- {evidence}\n+ const {key_name} = process.env.{key_name};\n+ if (!{key_name}) throw new Error(\"{key_name} is not configured\");"
        import_note = "Make sure the deployment environment defines this variable."
    else:
        after = f"Move `{key_name}` to the runtime environment or secret manager and remove the literal value from this file."
        diff = f"- {evidence}\n+ <load {key_name} from environment or secret manager>"
        import_note = "Non-code file detected; apply the equivalent config change manually."

    patch = _patch_base(
        finding,
        index,
        title=f"Move {key_name} to environment configuration",
        patch_type="env_secret_fix",
        before=evidence,
        after=after,
        diff=diff,
        explanation="Moves the secret out of committed source and fails safely when runtime configuration is missing.",
        confidence="medium",
    )
    patch["review_notes"].append(import_note)
    patch["review_notes"].append("Rotate the exposed secret; moving it after exposure is not enough.")
    return patch


def _tool_name(finding: dict) -> str:
    combined = f"{_title(finding)}\n{_evidence(finding)}"
    match = re.search(r"(?:def|function)\s+([a-zA-Z_][\w]*)", combined)
    if match:
        return match.group(1)
    match = re.search(r"['\"]([a-zA-Z_][\w]*)['\"]", combined)
    if match:
        return match.group(1)
    for hint in ("refund", "delete", "email", "shell", "execute", "customer", "payment", "database", "file"):
        if hint in combined.lower():
            return hint
    return "sensitive_tool_call"


def _approval_patch(finding: dict, index: int) -> dict:
    before = _evidence(finding) or "result = risky_tool_call(payload)"
    tool = _tool_name(finding)
    after = (
        f"approval = require_human_approval(action='{tool}', payload=payload)\n"
        "if not approval.approved:\n"
        "    raise PermissionError('Human approval required before this action')\n"
        f"result = {tool}(payload)"
    )
    diff = (
        f"- {before}\n"
        f"+ approval = require_human_approval(action='{tool}', payload=payload)\n"
        "+ if not approval.approved:\n"
        "+     raise PermissionError('Human approval required before this action')\n"
        f"+ result = {tool}(payload)"
    )
    return _patch_base(
        finding,
        index,
        title=f"Add human approval before `{tool}`",
        patch_type="human_approval_wrapper",
        before=before,
        after=after,
        diff=diff,
        explanation="Routes the risky action through an explicit human approval checkpoint before execution.",
        confidence="medium",
    )


def _audit_patch(finding: dict, index: int) -> dict:
    before = _evidence(finding) or "result = tool_call(payload)"
    tool = _tool_name(finding)
    after = (
        f"audit_log(event='tool_call_started', tool='{tool}', payload=redact(payload))\n"
        f"result = {tool}(payload)\n"
        f"audit_log(event='tool_call_completed', tool='{tool}', status='success')"
    )
    diff = (
        f"+ audit_log(event='tool_call_started', tool='{tool}', payload=redact(payload))\n"
        f"  {before}\n"
        f"+ audit_log(event='tool_call_completed', tool='{tool}', status='success')"
    )
    patch = _patch_base(
        finding,
        index,
        title=f"Add audit logging around `{tool}`",
        patch_type="audit_logging_addition",
        before=before,
        after=after,
        diff=diff,
        explanation="Adds traceability before and after the agent calls a critical tool.",
        confidence="medium",
    )
    patch["review_notes"].append("Redact secrets and PII before logging arguments.")
    return patch


def _pii_patch(finding: dict, index: int) -> dict:
    before = _evidence(finding) or "return customer_record"
    after = "safe_record = mask_sensitive_fields(customer_record, fields=['email', 'phone', 'address', 'token'])\nreturn safe_record"
    return _patch_base(
        finding,
        index,
        title="Mask sensitive fields before agent response",
        patch_type="pii_masking_helper",
        before=before,
        after=after,
        diff=f"- {before}\n+ safe_record = mask_sensitive_fields(customer_record, fields=['email', 'phone', 'address', 'token'])\n+ return safe_record",
        explanation="Reduces data exposure by masking sensitive customer fields before they reach the agent response.",
        confidence="medium",
    )


def _prompt_patch(finding: dict, index: int) -> dict:
    before = _evidence(finding) or "prompt = system_prompt + user_input"
    path = _file(finding)
    if _extension(path) == ".txt":
        after = "Load the system prompt from a protected runtime location and add prompt-injection tests for this prompt."
        diff = f"- committed prompt text in {path}\n+ runtime-loaded prompt with adversarial prompt tests"
        explanation = "A committed prompt file cannot be safely fixed by changing one line. Move it out of source or treat it as public and harden it accordingly."
        confidence = "low"
    else:
        after = "safe_user_input = sanitize_agent_input(user_input)\nprompt = f\"{system_prompt}\\n\\nUser request, treated as data only:\\n{safe_user_input}\""
        diff = f"- {before}\n+ safe_user_input = sanitize_agent_input(user_input)\n+ prompt = f\"{{system_prompt}}\\n\\nUser request, treated as data only:\\n{{safe_user_input}}\""
        explanation = "Separates system instructions from user-controlled text and treats user input as data."
        confidence = "medium"

    return _patch_base(
        finding,
        index,
        title="Add prompt boundary and input sanitization",
        patch_type="prompt_input_sanitization",
        before=before,
        after=after,
        diff=diff,
        explanation=explanation,
        confidence=confidence,
    )


def _tool_patch(finding: dict, index: int) -> dict:
    before = _evidence(finding) or "tools = [risky_tool]"
    tool = _tool_name(finding)
    after = f"tools = [scope_tool({tool}, allowed_actions=['read'], requires_approval=True, audit=True)]"
    return _patch_base(
        finding,
        index,
        title=f"Scope `{tool}` permissions",
        patch_type="tool_scope_guard",
        before=before,
        after=after,
        diff=f"- {before}\n+ {after}",
        explanation="Narrows the exposed tool capability, requires approval for high-impact use, and marks the call for audit logging.",
        confidence="low",
    )


def _patch_for_finding(finding: dict, index: int) -> dict | None:
    category = _category(finding)
    title = _title(finding).lower()
    if "secret" in category or "api key" in title or "token" in title:
        return _secret_patch(finding, index)
    if "human approval" in category or "approval" in title:
        return _approval_patch(finding, index)
    if "auditability" in category or "log" in title:
        return _audit_patch(finding, index)
    if "data exposure" in category or "pii" in title or "customer" in title:
        return _pii_patch(finding, index)
    if "prompt injection" in category or "prompt" in title:
        return _prompt_patch(finding, index)
    if "tool permission" in category or "tool" in title:
        return _tool_patch(finding, index)
    return None


def build_patch_previews(findings: list[dict], limit: int = 8) -> list[dict]:
    """Return safe developer-review patch previews linked to scanner findings."""
    patches: list[dict] = []
    for index, finding in enumerate(findings):
        patch = _patch_for_finding(finding, index)
        if patch:
            patches.append(patch)
        if len(patches) >= limit:
            break
    return patches
