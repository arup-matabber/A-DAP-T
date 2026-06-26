"""
Unit tests for Audit_Scanner.

Tests:
  - Audit keyword at exactly ±15 lines (boundary — should suppress finding)
  - Audit keyword at exactly ±16 lines (outside — should produce finding)
  - Severity downgrade: Critical tool → High audit; High tool → Medium audit
  - Missing file source lines handled gracefully (no exception)
  - All six audit keywords are recognised
  - Finding fields are populated correctly (req 9.5)

Requirements: 9.2, 9.3, 9.4, 9.5, 9.6
"""

from __future__ import annotations

import pytest

from app.scanners.secret_scanner import Finding
from app.scanners.audit_scanner import run, WINDOW_SIZE, AUDIT_KEYWORDS


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
        title="Risky tool: refund",
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
    keyword: str = "audit_log",
    total_lines: int = 120,
) -> str:
    """
    Return a multi-line string where `keyword` appears at center_line + offset
    (1-based), and every other line is a generic filler.
    """
    lines = [f"# line {i}" for i in range(1, total_lines + 1)]
    target = center_line - 1 + offset  # convert to 0-based index
    if 0 <= target < total_lines:
        lines[target] = f"    {keyword}('action happened')"
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Window boundary tests (req 9.2)
# ---------------------------------------------------------------------------

class TestWindowBoundary:
    """Keyword at exactly ±WINDOW_SIZE → suppressed; ±(WINDOW_SIZE+1) → finding."""

    def test_keyword_at_plus_boundary_suppresses(self):
        """Keyword placed at center + WINDOW_SIZE (15 lines after) — inside window."""
        finding = make_tool_finding(line=50)
        source = build_file_with_keyword_at_offset(center_line=50, offset=WINDOW_SIZE)
        result = run([finding], {"agent.py": source})
        assert result == [], "Keyword inside window should suppress the finding"

    def test_keyword_at_minus_boundary_suppresses(self):
        """Keyword placed at center - WINDOW_SIZE (15 lines before) — inside window."""
        finding = make_tool_finding(line=50)
        source = build_file_with_keyword_at_offset(center_line=50, offset=-WINDOW_SIZE)
        result = run([finding], {"agent.py": source})
        assert result == [], "Keyword inside window should suppress the finding"

    def test_keyword_at_plus_outside_produces_finding(self):
        """Keyword placed at center + WINDOW_SIZE + 1 (16 lines after) — outside window."""
        finding = make_tool_finding(line=50)
        source = build_file_with_keyword_at_offset(center_line=50, offset=WINDOW_SIZE + 1)
        result = run([finding], {"agent.py": source})
        assert len(result) == 1, "Keyword outside window should produce a finding"

    def test_keyword_at_minus_outside_produces_finding(self):
        """Keyword placed at center - WINDOW_SIZE - 1 (16 lines before) — outside window."""
        finding = make_tool_finding(line=50)
        source = build_file_with_keyword_at_offset(center_line=50, offset=-(WINDOW_SIZE + 1))
        result = run([finding], {"agent.py": source})
        assert len(result) == 1, "Keyword outside window should produce a finding"

    def test_no_keyword_produces_finding(self):
        """File has no audit keyword anywhere."""
        finding = make_tool_finding(line=10)
        source = "\n".join(f"# line {i}" for i in range(1, 30))
        result = run([finding], {"agent.py": source})
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Severity downgrade tests (req 9.3)
# ---------------------------------------------------------------------------

class TestSeverityDowngrade:
    """Critical tool → High audit; High tool → Medium audit."""

    def _source_without_keywords(self, lines: int = 30) -> str:
        return "\n".join(f"# line {i}" for i in range(1, lines + 1))

    def test_critical_tool_produces_high_audit_finding(self):
        finding = make_tool_finding(line=10, severity="Critical")
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert len(result) == 1
        assert result[0].severity == "High"

    def test_high_tool_produces_medium_audit_finding(self):
        finding = make_tool_finding(line=10, severity="High")
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert len(result) == 1
        assert result[0].severity == "Medium"


# ---------------------------------------------------------------------------
# Finding field correctness (req 9.5)
# ---------------------------------------------------------------------------

class TestFindingFields:
    """Verify all required fields are populated correctly."""

    def _source_without_keywords(self) -> str:
        return "\n".join(f"# line {i}" for i in range(1, 30))

    def test_finding_category(self):
        finding = make_tool_finding(line=5)
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert result[0].category == "Auditability Risk"

    def test_finding_file_matches_tool_finding(self):
        finding = make_tool_finding(filepath="src/tools.py", line=5)
        source = self._source_without_keywords()
        result = run([finding], {"src/tools.py": source})
        assert result[0].file == "src/tools.py"

    def test_finding_line_matches_tool_finding(self):
        finding = make_tool_finding(line=7)
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert result[0].line == 7

    def test_finding_has_non_empty_title(self):
        finding = make_tool_finding(line=5)
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert result[0].title  # non-empty string

    def test_finding_has_non_empty_why_it_matters(self):
        finding = make_tool_finding(line=5)
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert result[0].why_it_matters

    def test_finding_has_non_empty_suggested_fix(self):
        finding = make_tool_finding(line=5)
        result = run([finding], {"agent.py": self._source_without_keywords()})
        assert result[0].suggested_fix


# ---------------------------------------------------------------------------
# Graceful handling of missing file (req 9.6)
# ---------------------------------------------------------------------------

class TestMissingFile:
    """Findings for files not in `files` dict are silently skipped."""

    def test_missing_file_does_not_raise(self):
        finding = make_tool_finding(filepath="missing.py", line=1)
        # "missing.py" is not in the files dict
        result = run([finding], {})
        assert result == []

    def test_other_findings_still_processed_when_one_file_missing(self):
        present = make_tool_finding(filepath="present.py", line=5)
        absent = make_tool_finding(filepath="missing.py", line=5)
        source = "\n".join(f"# line {i}" for i in range(1, 20))
        result = run([present, absent], {"present.py": source})
        # Only the present file produces a finding; absent file is skipped
        assert len(result) == 1
        assert result[0].file == "present.py"


# ---------------------------------------------------------------------------
# All audit keywords are recognised (req 9.2)
# ---------------------------------------------------------------------------

class TestAllKeywordsRecognised:
    """Each of the six audit keywords should suppress a finding when in window."""

    @pytest.mark.parametrize("keyword", AUDIT_KEYWORDS)
    def test_keyword_suppresses_finding(self, keyword: str):
        finding = make_tool_finding(line=30)
        source = build_file_with_keyword_at_offset(
            center_line=30, offset=0, keyword=keyword
        )
        result = run([finding], {"agent.py": source})
        assert result == [], f"Keyword '{keyword}' inside window should suppress finding"

    @pytest.mark.parametrize("keyword", AUDIT_KEYWORDS)
    def test_keyword_case_insensitive(self, keyword: str):
        """Keywords are matched case-insensitively (req 9.2)."""
        finding = make_tool_finding(line=30)
        source = build_file_with_keyword_at_offset(
            center_line=30, offset=0, keyword=keyword.upper()
        )
        result = run([finding], {"agent.py": source})
        assert result == [], f"Uppercase '{keyword.upper()}' should still suppress finding"


# ---------------------------------------------------------------------------
# Multiple findings in the same file
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    """Multiple tool findings from the same file are handled independently."""

    def test_two_findings_both_without_keywords(self):
        source = "\n".join(f"# line {i}" for i in range(1, 60))
        findings = [
            make_tool_finding(line=10),
            make_tool_finding(line=40),
        ]
        result = run(findings, {"agent.py": source})
        assert len(result) == 2

    def test_one_finding_with_keyword_one_without(self):
        # keyword at line 25, finding at line 10 (25-10=15 → exactly in window → suppressed)
        # finding at line 45 → keyword is 20 lines away → outside window → produces finding
        source = build_file_with_keyword_at_offset(
            center_line=10, offset=WINDOW_SIZE, total_lines=80
        )
        f1 = make_tool_finding(line=10)
        f2 = make_tool_finding(line=45)
        result = run([f1, f2], {"agent.py": source})
        assert len(result) == 1
        assert result[0].line == 45
