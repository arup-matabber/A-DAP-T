import re
from collections import Counter
from typing import Any, Dict, List

MAX_BULLETS = 5
MAX_BULLET_WORDS = 18
MAX_SUMMARY_WORDS = 38
MAX_REPORT_LINES = 4


_LIST_MARKER_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")
_MD_RE = re.compile(r"[*_`#>]+")


def _clean_text(value: Any) -> str:
    text = str(value or "")
    text = _MD_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _word_limit(text: str, max_words: int) -> str:
    clean = _clean_text(text)
    words = clean.split()
    if len(words) <= max_words:
        return " ".join(words)

    # Report cards should never show half-cut remediation text. Prefer a full
    # sentence that fits; otherwise end the shortened text cleanly with a period.
    sentences = re.split(r"(?<=[.!?])\s+", clean)
    kept = []
    total = 0
    for sentence in sentences:
        count = len(sentence.split())
        if kept and total + count > max_words:
            break
        if count <= max_words:
            kept.append(sentence.strip())
            total += count
        else:
            break

    if kept:
        result = " ".join(kept).strip()
    else:
        result = " ".join(words[:max_words]).rstrip(".,;:")

    return result if result.endswith(('.', '!', '?')) else result + "."


def _normalise_severity(value: Any) -> str:
    return str(value or "").strip().lower()


def _risk_status(score: Any, status: Any) -> str:
    if status:
        return str(status)
    try:
        val = int(score)
    except Exception:
        return "Unknown Risk"

    if val < 40:
        return "High Risk"
    if val < 75:
        return "Moderate Risk"
    return "Low Risk"


def _finding_counts(findings: List[dict]) -> tuple[int, int]:
    critical = sum(1 for item in findings if _normalise_severity(item.get("severity")) == "critical")
    high = sum(1 for item in findings if _normalise_severity(item.get("severity")) == "high")
    return critical, high


def _top_categories(scan_result: Dict[str, Any], limit: int = 2) -> List[str]:
    scores = scan_result.get("category_scores") or {}
    if isinstance(scores, dict) and scores:
        ordered = sorted(scores.items(), key=lambda item: item[1] if isinstance(item[1], (int, float)) else 0, reverse=True)
        return [_category_label(key) for key, _ in ordered[:limit]]

    findings = scan_result.get("findings") or []
    counts = Counter(item.get("category", "Unknown Risk") for item in findings)
    return [name for name, _ in counts.most_common(limit)]


def _category_label(key: str) -> str:
    labels = {
        "prompt_injection": "prompt injection",
        "secret_exposure": "secret exposure",
        "tool_permission": "tool permission",
        "human_approval": "human approval",
        "data_exposure": "data exposure",
        "auditability": "auditability",
    }
    return labels.get(str(key), str(key).replace("_", " "))


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        clean = _clean_text(item)
        if not clean:
            continue
        key = clean.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(clean)
    return result


def _complete_bullet(text: Any) -> str:
    clean = _LIST_MARKER_RE.sub("", str(text or "")).strip()
    clean = _word_limit(clean, MAX_BULLET_WORDS)
    return clean if clean.endswith((".", "!", "?")) else clean + "."


def _compact_bullets(items: List[Any], max_items: int = MAX_BULLETS) -> List[str]:
    bullets = []
    for item in items:
        text = _complete_bullet(item)
        if text:
            bullets.append(text)
    return _dedupe(bullets)[:max_items]


def _fix_from_finding(finding: Dict[str, Any]) -> str:
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()

    if "secret" in category or "api key" in title or "token" in title or "jwt" in title:
        return "Move hardcoded secrets to environment variables."
    if "approval" in category or "approval" in title:
        return "Add an approval gate before sensitive actions."
    if "tool" in category or "function" in title or "tool" in title:
        return "Restrict risky tool calls to approved scopes."
    if "data" in category or "pii" in title or "customer" in title:
        return "Mask sensitive customer data before agent use."
    if "audit" in category or "log" in title:
        return "Log every critical tool invocation."
    if "prompt" in category or "prompt" in title or "injection" in title:
        return "Harden prompts against injection and leakage."

    return "Fix this finding before deployment."


def _summary(scan_result: Dict[str, Any]) -> str:
    project = scan_result.get("project_name", "this project")
    score = scan_result.get("safety_score", "unknown")
    status = _risk_status(score, scan_result.get("status"))
    findings = scan_result.get("findings") or []
    critical, high = _finding_counts(findings)
    categories = _top_categories(scan_result, 2)
    category_text = " and ".join(categories) if categories else "agent deployment"

    text = (
        f"{project} scored {score}/100 ({status}). "
        f"A-DAP-T found {critical} critical and {high} high-severity issues, mainly around {category_text}."
    )
    return _word_limit(text, MAX_SUMMARY_WORDS)


def _report_summary(scan_result: Dict[str, Any]) -> str:
    project = scan_result.get("project_name", "this project")
    score = scan_result.get("safety_score", "unknown")
    status = _risk_status(score, scan_result.get("status"))
    findings = scan_result.get("findings") or []
    critical, high = _finding_counts(findings)
    categories = _top_categories(scan_result, 3)
    category_text = ", ".join(categories) if categories else "agent deployment controls"

    lines = [
        f"A-DAP-T scanned {project} and assigned a safety score of {score}/100 ({status}).",
        f"The scan found {critical} critical and {high} high-severity issues across {category_text}.",
        "Prioritize exposed secrets, unsafe tool access, approval gaps, and sensitive data handling before deployment.",
        "Use the findings below for exact files, reasons, and fixes.",
    ]
    return "\n".join(lines[:MAX_REPORT_LINES])


def _remediation_plan(scan_result: Dict[str, Any]) -> List[str]:
    findings = scan_result.get("findings") or []
    priority = []

    for severity in ("critical", "high", "medium"):
        for finding in findings:
            if _normalise_severity(finding.get("severity")) != severity:
                continue
            priority.append(_fix_from_finding(finding))

    if not priority:
        priority = scan_result.get("remediation_checklist") or []

    fallback = [
        "Move hardcoded secrets to environment variables.",
        "Add approval gates before sensitive tool calls.",
        "Mask customer data before agent use.",
        "Store prompts outside committed source files.",
        "Log every critical tool invocation.",
    ]
    return _compact_bullets(priority or fallback)


def _next_steps(scan_result: Dict[str, Any]) -> List[str]:
    findings = scan_result.get("findings") or []
    categories = {str(item.get("category", "")).lower() for item in findings}

    steps = []
    if any("secret" in cat for cat in categories):
        steps.append("Fix critical secret exposure findings first.")
    if any("tool" in cat for cat in categories):
        steps.append("Review high-risk tool permissions.")
    if any("approval" in cat for cat in categories):
        steps.append("Add approval checks for sensitive actions.")
    if any("data" in cat for cat in categories):
        steps.append("Mask or remove sensitive customer data.")
    if any("audit" in cat for cat in categories):
        steps.append("Add logs for critical tool invocations.")

    steps.append("Retest the project after fixes.")
    return _compact_bullets(steps)


def enrich_scan_result_with_ai(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add compact report-safe explanation fields.

    Detailed conversation belongs in DAP. Report cards need predictable, short text,
    so this layer generates bounded summaries from the rule-based scan result.
    """

    enriched_result = dict(scan_result)
    enriched_result["ai_summary"] = _summary(scan_result)
    enriched_result["ai_report_summary"] = _report_summary(scan_result)
    enriched_result["ai_remediation_plan"] = _remediation_plan(scan_result)
    enriched_result["ai_next_steps"] = _next_steps(scan_result)
    enriched_result["ai_enrichment_status"] = "compact_report_ready"
    return enriched_result
