from __future__ import annotations
import math
from app.scanners.secret_scanner import Finding

# Severity Weights (Task Group 5)
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 15,
    "Low": 5,
    "Info": 0
}

# Category Weights (Task Group 5)
CATEGORY_WEIGHTS = {
    "Prompt Injection Risk": 0.25,
    "Secret Exposure Risk": 0.20,
    "Tool Permission Risk": 0.20,
    "Human Approval Risk": 0.15,
    "Data Exposure Risk": 0.10,
    "Auditability Risk": 0.10,
}

# Maps standard finding category names to schema fields
CATEGORY_TO_SCHEMA_KEY = {
    "Prompt Injection Risk": "prompt_injection",
    "Secret Exposure Risk": "secret_exposure",
    "Tool Permission Risk": "tool_permission",
    "Human Approval Risk": "human_approval",
    "Data Exposure Risk": "data_exposure",
    "Auditability Risk": "auditability"
}


def normalize_category(cat: str) -> str:
    """Normalize category name case-insensitively with/without 'Risk' suffix."""
    c = cat.lower().strip()
    if "prompt injection" in c:
        return "Prompt Injection Risk"
    if "secret exposure" in c:
        return "Secret Exposure Risk"
    if "tool permission" in c:
        return "Tool Permission Risk"
    if "human approval" in c:
        return "Human Approval Risk"
    if "data exposure" in c:
        return "Data Exposure Risk"
    if "auditability" in c or "audit" in c:
        return "Auditability Risk"
    return cat


def compute_category_score(findings: list[Finding], category: str) -> int:
    """
    Compute score for a single category: min(sum(severity_weights), 100).
    Filters findings by category, handles unknown categories safely.
    """
    target = normalize_category(category)
    total_weight = 0
    for f in findings:
        f_cat = normalize_category(f.category)
        if f_cat == target:
            weight = SEVERITY_WEIGHTS.get(f.severity.capitalize(), 0)
            total_weight += weight
    return min(total_weight, 100)


def compute_overall_risk(category_scores: dict[str, int]) -> float:
    """
    Calculate weighted overall risk score based on individual category scores.
    Handles category names in both schemas and Finding formats.
    """
    overall_risk = 0.0
    for cat, weight in CATEGORY_WEIGHTS.items():
        # Check by Finding format category
        score = category_scores.get(cat)
        if score is None:
            # Check by schema key
            schema_key = CATEGORY_TO_SCHEMA_KEY.get(cat)
            score = category_scores.get(schema_key, 0) if schema_key else 0
        overall_risk += score * weight
    return overall_risk


def compute_safety_score(overall_risk: float) -> int:
    """Calculate safety score: round(100 - overall_risk) clamped to 0..100."""
    score = round(100.0 - overall_risk)
    return max(0, min(100, score))


def compute_status(safety_score: int) -> str:
    """Map safety score to status tier."""
    if 0 <= safety_score <= 25:
        return "Critical Risk"
    if 26 <= safety_score <= 50:
        return "High Risk"
    if 51 <= safety_score <= 75:
        return "Moderate Risk"
    if 76 <= safety_score <= 90:
        return "Low Risk"
    return "Strong"


def compute_summary(findings: list[Finding]) -> dict[str, int]:
    """Count critical, high, medium, and low findings (ignoring Info)."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts
