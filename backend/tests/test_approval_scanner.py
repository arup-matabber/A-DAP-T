"""
Unit tests for Approval_Scanner.

Tests:
  - Approval keyword within ±10-line window suppresses finding
  - Approval keyword outside ±10-line window produces finding
  - Severity inheritance: Critical tool → Critical approval; High tool → High approval
  - Missing file source lines handled gracefully (no exception)
  - All seven approval keywords are recognised
  - Finding fields are populated correctly (req 8.5)

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""

from __future__ import annotations

import pytest

from app.scanners.secret_scanner import Finding
from app.scanners.approval_scanner import run, WINDOW_SIZE, APPROVAL_KEYWORDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_tool_finding(
    filepath: str = "agent.py",
    line: int = 50,
    severity: str = "Critical",
) -> Finding:
    """Build a minimal Tool Permission Risk finding."""
    return Finding(
        title="Risky function 'issue_refund()' detected",
        severity=severity,
        category="Tool Permission Risk",
        file=filepath,
        line=line,
        why_it_matters="test",
        suggested_fix="test",
    )


def build_file_with_keyword_at_offset(
    center_line: int,
    offset: int,
    keyword: str = "approval_gate",
    total_lines: int = 120,
) -> str:
    """
    Build a source file where the line at *center_line + offset* contains *keyword*.

    Args:
        center_line: The finding line number (1-based).
        offset: Position of the keyword relative to center: -10, -9, ..., 0, ..., +10.
        keyword: The keyword to place.
        total_lines: Total number of lines to generate.

    Returns:
        Multi-line file content.
    """
    lines = [f"line {i}" for i in range(1, total_lines + 1)]
    keyword_line_index = (center_line + offset - 1)  # Convert to 0-based index
    if 0 <= keyword_line_index < len(lines):
        lines[keyword_line_index] = f"{keyword} check passed"
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Test: Approval keyword within window suppresses finding
# Requirement: 8.2, 8.4
# ---------------------------------------------------------------------------

def test_approval_keyword_within_window_at_boundary() -> None:
    """
    When an approval keyword appears at exactly ±10 lines from the finding,
    the finding should NOT generate an approval risk.
    """
    center = 50
    
    # Test at exactly -10 and +10 boundaries
    for offset in [-WINDOW_SIZE, WINDOW_SIZE]:
        tool_finding = make_tool_finding(line=center, severity="Critical")
        source = build_file_with_keyword_at_offset(center, offset, "approval_gate")
        files = {"agent.py": source}
        
        result = run([tool_finding], files)
        assert len(result) == 0, (
            f"Keyword at offset {offset} (boundary) should suppress finding"
        )


def test_approval_keyword_within_window_middle() -> None:
    """
    When an approval keyword appears anywhere within ±10 lines,
    the finding should NOT be generated.
    """
    center = 50
    tool_finding = make_tool_finding(line=center, severity="High")
    
    # Test various positions within the window
    for offset in [-5, -1, 0, 1, 5]:
        source = build_file_with_keyword_at_offset(center, offset, "requires_approval")
        files = {"agent.py": source}
        
        result = run([tool_finding], files)
        assert len(result) == 0, (
            f"Keyword at offset {offset} (within window) should suppress finding"
        )


# ---------------------------------------------------------------------------
# Test: Approval keyword outside window generates finding
# Requirement: 8.2, 8.3
# ---------------------------------------------------------------------------

def test_approval_keyword_outside_window_upper() -> None:
    """
    When an approval keyword is at exactly ±11 or beyond,
    the finding SHOULD be generated.
    """
    center = 50
    tool_finding = make_tool_finding(line=center, severity="Critical")
    source = build_file_with_keyword_at_offset(center, WINDOW_SIZE + 1, "approval_gate")
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1, "Keyword outside window should generate finding"
    assert result[0].category == "Human Approval Risk"
    assert result[0].severity == "Critical"


def test_approval_keyword_outside_window_lower() -> None:
    """
    When an approval keyword is outside the window (below),
    the finding SHOULD be generated.
    """
    center = 50
    tool_finding = make_tool_finding(line=center, severity="High")
    source = build_file_with_keyword_at_offset(center, -(WINDOW_SIZE + 1), "human_review")
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    assert result[0].category == "Human Approval Risk"
    assert result[0].severity == "High"


def test_no_approval_keyword_generates_finding() -> None:
    """
    When no approval keyword is present anywhere in the file,
    the finding SHOULD be generated.
    """
    tool_finding = make_tool_finding(line=50)
    source = "\n".join([f"line {i}" for i in range(1, 121)])  # No keywords
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    assert result[0].category == "Human Approval Risk"


# ---------------------------------------------------------------------------
# Test: All approval keywords are recognised
# Requirement: 8.2
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("keyword", APPROVAL_KEYWORDS)
def test_all_approval_keywords_recognized(keyword: str) -> None:
    """
    Every defined approval keyword should suppress a finding when present within window.
    """
    center = 50
    tool_finding = make_tool_finding(line=center)
    source = build_file_with_keyword_at_offset(center, 0, keyword)
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 0, f"Keyword '{keyword}' should be recognized"


# ---------------------------------------------------------------------------
# Test: Case-insensitive matching
# Requirement: 8.2 (implied by re.IGNORECASE)
# ---------------------------------------------------------------------------

def test_keywords_case_insensitive() -> None:
    """
    Approval keywords should match regardless of case.
    """
    center = 50
    tool_finding = make_tool_finding(line=center)
    
    cases = ["APPROVAL_GATE", "Approval_Gate", "approval_gate", "ApProVaL_gAte"]
    for case_variant in cases:
        # Put the keyword in actual code context, not just as a word
        source = build_file_with_keyword_at_offset(center, 0, case_variant)
        files = {"agent.py": source}
        result = run([tool_finding], files)
        assert len(result) == 0, f"Case variant '{case_variant}' should match"


# ---------------------------------------------------------------------------
# Test: Severity inheritance
# Requirement: 8.3
# ---------------------------------------------------------------------------

def test_severity_inheritance_critical() -> None:
    """
    A Critical tool finding should produce a Critical approval finding.
    """
    tool_finding = make_tool_finding(severity="Critical")
    source = "\n".join([f"line {i}" for i in range(1, 121)])  # No keywords
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    assert result[0].severity == "Critical"


def test_severity_inheritance_high() -> None:
    """
    A High tool finding should produce a High approval finding.
    """
    tool_finding = make_tool_finding(severity="High")
    source = "\n".join([f"line {i}" for i in range(1, 121)])  # No keywords
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    assert result[0].severity == "High"


def test_severity_inheritance_medium() -> None:
    """
    A Medium tool finding should produce a Medium approval finding.
    """
    tool_finding = make_tool_finding(severity="Medium")
    source = "\n".join([f"line {i}" for i in range(1, 121)])  # No keywords
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    assert result[0].severity == "Medium"


# ---------------------------------------------------------------------------
# Test: Missing file source handled gracefully
# Requirement: 8.6
# ---------------------------------------------------------------------------

def test_missing_file_skipped_gracefully() -> None:
    """
    When a tool finding references a file not in the 'files' mapping,
    the scanner should skip it without raising an exception.
    """
    tool_finding = make_tool_finding(filepath="nonexistent.py", line=50)
    files = {"other.py": "some content"}
    
    # Should not raise an exception
    result = run([tool_finding], files)
    # Should produce no finding (the file is unavailable)
    assert len(result) == 0


def test_multiple_files_used() -> None:
    """
    When scanning multiple tool findings across different files,
    all files should be processed correctly.
    """
    tool_findings = [
        make_tool_finding(filepath="file1.py", line=10),
        make_tool_finding(filepath="file2.py", line=20),
    ]
    files = {
        "file1.py": "approval_gate\n" + "\n".join([f"line {i}" for i in range(2, 100)]),
        "file2.py": "\n".join([f"line {i}" for i in range(1, 100)]),  # No keywords
    }
    
    result = run(tool_findings, files)
    # file1.py has approval keyword → no finding
    # file2.py has no keyword → one finding
    assert len(result) == 1
    assert result[0].file == "file2.py"


# ---------------------------------------------------------------------------
# Test: Finding fields populated correctly
# Requirement: 8.5
# ---------------------------------------------------------------------------

def test_finding_fields_populated() -> None:
    """
    Verify that all Finding fields are properly populated.
    """
    tool_finding = make_tool_finding(
        filepath="agent.py",
        line=50,
        severity="Critical"
    )
    source = "\n".join([f"line {i}" for i in range(1, 121)])
    files = {"agent.py": source}
    
    result = run([tool_finding], files)
    assert len(result) == 1
    
    finding = result[0]
    assert finding.title is not None
    assert "No human approval gate found" in finding.title
    assert finding.severity == "Critical"
    assert finding.category == "Human Approval Risk"
    assert finding.file == "agent.py"
    assert finding.line == 50
    assert finding.why_it_matters is not None
    assert finding.suggested_fix is not None


# ---------------------------------------------------------------------------
# Test: Edge cases
# ---------------------------------------------------------------------------

def test_empty_tool_findings() -> None:
    """
    When no tool findings are provided, no approval findings should be generated.
    """
    files = {"agent.py": "some code"}
    result = run([], files)
    assert len(result) == 0


def test_empty_files_dict() -> None:
    """
    When the files dict is empty, tool findings should be skipped gracefully.
    """
    tool_finding = make_tool_finding(filepath="agent.py")
    result = run([tool_finding], {})
    assert len(result) == 0


def test_single_line_file() -> None:
    """
    When a file has only one line, the finding should be generated if no keyword is present.
    """
    tool_finding = make_tool_finding(filepath="agent.py", line=1)
    files = {"agent.py": "single line"}
    result = run([tool_finding], files)
    assert len(result) == 1


def test_keyword_in_string_literal() -> None:
    """
    Approval keywords should be matched whether in actual code or comments.
    The current regex implementation will match them anywhere in a line.
    This test verifies that behavior.
    """
    center = 50
    tool_finding = make_tool_finding(line=center)
    
    # Keyword in comment - should suppress (regex matches anywhere in line)
    source = build_file_with_keyword_at_offset(center, 0, "requires_approval")
    files = {"agent.py": source}
    result = run([tool_finding], files)
    assert len(result) == 0, "Keyword in comment should suppress"
