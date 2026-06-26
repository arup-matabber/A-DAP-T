import pytest
from app.scanners.secret_scanner import Finding
from app.risk.scoring import (
    compute_category_score,
    compute_overall_risk,
    compute_safety_score,
    compute_status,
    compute_summary
)

def test_compute_category_score():
    findings = [
        Finding("Critical key", "Critical", "Secret Exposure Risk", "f.py", 1, "", ""),
        Finding("High url", "High", "Secret Exposure Risk", "f.py", 2, "", ""),
    ]
    # Critical (40) + High (25) = 65
    score = compute_category_score(findings, "Secret Exposure Risk")
    assert score == 65

    # Test clamping
    findings_many = [
        Finding("Critical 1", "Critical", "Secret Exposure Risk", "f.py", 1, "", ""),
        Finding("Critical 2", "Critical", "Secret Exposure Risk", "f.py", 2, "", ""),
        Finding("Critical 3", "Critical", "Secret Exposure Risk", "f.py", 3, "", ""),
    ]
    # 3 * 40 = 120 -> clamped to 100
    assert compute_category_score(findings_many, "Secret Exposure Risk") == 100

def test_compute_overall_risk():
    category_scores = {
        "Secret Exposure Risk": 100,  # weight 0.20 -> 20.0
        "Prompt Injection Risk": 50,  # weight 0.25 -> 12.5
    }
    # Total = 32.5
    overall = compute_overall_risk(category_scores)
    assert overall == 32.5

def test_compute_safety_score():
    assert compute_safety_score(32.5) == 68  # 100 - 32.5 = 67.5 -> round to 68
    assert compute_safety_score(150.0) == 0  # clamped to 0
    assert compute_safety_score(-10.0) == 100 # clamped to 100

def test_compute_status():
    assert compute_status(20) == "Critical Risk"
    assert compute_status(35) == "High Risk"
    assert compute_status(60) == "Moderate Risk"
    assert compute_status(80) == "Low Risk"
    assert compute_status(95) == "Strong"

def test_compute_summary():
    findings = [
        Finding("F1", "Critical", "Secret Exposure Risk", "f.py", 1, "", ""),
        Finding("F2", "High", "Secret Exposure Risk", "f.py", 2, "", ""),
        Finding("F3", "Medium", "Secret Exposure Risk", "f.py", 3, "", ""),
        Finding("F4", "Low", "Secret Exposure Risk", "f.py", 4, "", ""),
        Finding("F5", "Info", "Secret Exposure Risk", "f.py", 5, "", ""),
    ]
    summary = compute_summary(findings)
    assert summary == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1
    }
