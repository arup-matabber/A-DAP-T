"""
Property-based tests for Tool_Scanner.

Tests are tagged with the property number defined in design.md for traceability.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from app.scanners.tool_scanner import (
    DATA_ACCESS_KEYWORDS,
    DATA_EXPOSURE_WINDOW,
    MASKING_KEYWORDS,
    run,
)

# ---------------------------------------------------------------------------
# Feature: adapt-backend-scanner
# Property 17: Data exposure — unmasked data-access function is always flagged
# Validates: Requirements 17.2
# ---------------------------------------------------------------------------

# The data-access keywords that are NOT also risky tool keywords so we get
# only Data Exposure Risk findings (not Tool Permission Risk findings mixed in).
# All DATA_ACCESS_KEYWORDS are safe to use directly since none overlap with the
# CRITICAL or HIGH tool permission keywords.
_DATA_ACCESS_ST = st.sampled_from(DATA_ACCESS_KEYWORDS)
_MASKING_ST = st.sampled_from(MASKING_KEYWORDS)


def _build_py_source(
    func_keyword: str,
    masking_keyword: str | None,
    masking_offset: int,
    total_padding: int = 25,
) -> tuple[str, int]:
    """
    Build a minimal Python source file (as a string) that contains a
    ``def <func_with_keyword>(...)`` definition and, optionally, a line
    containing *masking_keyword* at a given line offset.

    Returns (source_text, func_line_number) where func_line_number is
    1-based.

    *masking_offset* is the signed offset from the function line at which the
    masking keyword is placed (e.g. -5 means 5 lines above, +7 means 7 lines
    below).  Pass ``None`` for *masking_keyword* to omit masking entirely.
    """
    # Place the function definition in the middle of a block of blank lines
    # so there is always room for the masking keyword at any offset within the
    # test range.
    before_lines = ["# padding\n"] * total_padding
    func_line = f"def {func_keyword}_impl(data):\n"
    func_line_number = total_padding + 1  # 1-based

    # Build an array of lines after the function definition (body + padding)
    after_lines = ["    return data\n"] + ["# padding\n"] * total_padding

    all_lines: list[str] = before_lines + [func_line] + after_lines

    if masking_keyword is not None:
        # Insert masking keyword at the requested offset
        masking_line_index = (func_line_number - 1) + masking_offset  # 0-based
        # Clamp to valid range
        masking_line_index = max(0, min(len(all_lines) - 1, masking_line_index))
        all_lines[masking_line_index] = f"    result = {masking_keyword}field(data)\n"

    return "".join(all_lines), func_line_number


# ---------------------------------------------------------------------------
# Sub-property 17a: Without masking in window → at least 1 Data Exposure Risk
# ---------------------------------------------------------------------------


@given(
    func_kw=_DATA_ACCESS_ST,
    masking_kw=_MASKING_ST,
    # Place masking OUTSIDE the window: offset in [11, 20] or [-20, -11]
    outside_offset=st.one_of(
        st.integers(min_value=DATA_EXPOSURE_WINDOW + 1, max_value=20),
        st.integers(min_value=-20, max_value=-(DATA_EXPOSURE_WINDOW + 1)),
    ),
)
@settings(max_examples=200)
def test_data_exposure_no_masking_in_window_always_flagged(
    func_kw: str,
    masking_kw: str,
    outside_offset: int,
) -> None:
    """
    Feature: adapt-backend-scanner, Property 17 (sub-property a):
    Data exposure — masking keyword placed OUTSIDE ±10-line window still
    produces at least one Data Exposure Risk finding.

    Validates: Requirements 17.2
    """
    source, _func_lineno = _build_py_source(
        func_keyword=func_kw,
        masking_keyword=masking_kw,
        masking_offset=outside_offset,
        total_padding=25,
    )

    findings = run({"agent.py": source})

    data_exposure_findings = [
        f for f in findings if f.category == "Data Exposure Risk"
    ]

    assert len(data_exposure_findings) >= 1, (
        f"Expected ≥1 'Data Exposure Risk' finding for function containing "
        f"'{func_kw}' with masking '{masking_kw}' placed at offset "
        f"{outside_offset} (outside ±{DATA_EXPOSURE_WINDOW}-line window), "
        f"but got {len(data_exposure_findings)} finding(s).\n"
        f"All findings: {findings}"
    )


@given(func_kw=_DATA_ACCESS_ST)
@settings(max_examples=100)
def test_data_exposure_no_masking_at_all_always_flagged(func_kw: str) -> None:
    """
    Feature: adapt-backend-scanner, Property 17 (sub-property a2):
    Data exposure — completely absent masking keyword always produces a
    Data Exposure Risk finding.

    Validates: Requirements 17.2
    """
    source, _func_lineno = _build_py_source(
        func_keyword=func_kw,
        masking_keyword=None,
        masking_offset=0,
        total_padding=25,
    )

    findings = run({"agent.py": source})

    data_exposure_findings = [
        f for f in findings if f.category == "Data Exposure Risk"
    ]

    assert len(data_exposure_findings) >= 1, (
        f"Expected ≥1 'Data Exposure Risk' finding for function containing "
        f"'{func_kw}' with no masking keyword present, "
        f"but got {len(data_exposure_findings)} finding(s).\n"
        f"All findings: {findings}"
    )


# ---------------------------------------------------------------------------
# Sub-property 17b: With masking keyword INSIDE window → 0 Data Exposure Risk
# ---------------------------------------------------------------------------


@given(
    func_kw=_DATA_ACCESS_ST,
    masking_kw=_MASKING_ST,
    # Place masking INSIDE the window: offset in [-10, 10]
    inside_offset=st.integers(
        min_value=-DATA_EXPOSURE_WINDOW, max_value=DATA_EXPOSURE_WINDOW
    ),
)
@settings(max_examples=200)
def test_data_exposure_masking_in_window_suppresses_finding(
    func_kw: str,
    masking_kw: str,
    inside_offset: int,
) -> None:
    """
    Feature: adapt-backend-scanner, Property 17 (sub-property b):
    Data exposure — masking keyword placed WITHIN ±10-line window suppresses
    the Data Exposure Risk finding (0 findings for that function).

    Validates: Requirements 17.2
    """
    source, func_lineno = _build_py_source(
        func_keyword=func_kw,
        masking_keyword=masking_kw,
        masking_offset=inside_offset,
        total_padding=25,
    )

    findings = run({"agent.py": source})

    data_exposure_findings = [
        f for f in findings if f.category == "Data Exposure Risk"
    ]

    assert len(data_exposure_findings) == 0, (
        f"Expected 0 'Data Exposure Risk' findings for function containing "
        f"'{func_kw}' with masking '{masking_kw}' placed at offset "
        f"{inside_offset} (inside ±{DATA_EXPOSURE_WINDOW}-line window), "
        f"but got {len(data_exposure_findings)} finding(s).\n"
        f"Source around function line {func_lineno}:\n{source}\n"
        f"All findings: {findings}"
    )


# ---------------------------------------------------------------------------
# Feature: adapt-backend-scanner
# Property 9: Risky tool detection — any matching function name is flagged
# Validates: Requirements 7.2, 7.3
# ---------------------------------------------------------------------------

from app.scanners.tool_scanner import (
    CRITICAL_TOOL_KEYWORDS,
    HIGH_TOOL_KEYWORDS,
)

_CRITICAL_KEYWORDS = CRITICAL_TOOL_KEYWORDS
_HIGH_KEYWORDS = HIGH_TOOL_KEYWORDS

# Generate a safe identifier fragment to wrap around the keyword
# (letters, digits and underscores only — valid in a Python/JS identifier)
_IDENT_FRAGMENT_ST = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="_",
    ),
    min_size=0,
    max_size=10,
)


def _make_py_func_source(func_name: str) -> str:
    """Return minimal Python source with one function definition."""
    return f"def {func_name}(arg1, arg2):\n    pass\n"


def _make_js_func_source(func_name: str) -> str:
    """Return minimal JavaScript/TypeScript source with one function definition."""
    return f"function {func_name}(arg1, arg2) {{\n    return null;\n}}\n"


@given(
    keyword=st.sampled_from(_CRITICAL_KEYWORDS),
    prefix=_IDENT_FRAGMENT_ST,
    suffix=_IDENT_FRAGMENT_ST,
)
@settings(max_examples=200)
def test_critical_keyword_in_python_function_produces_one_critical_finding(
    keyword: str, prefix: str, suffix: str
) -> None:
    """
    Feature: adapt-backend-scanner, Property 9: Risky tool detection.

    For any Python function definition whose name contains a critical-tier
    keyword (case-insensitive), Tool_Scanner.run() SHALL produce exactly one
    Finding with category 'Tool Permission Risk' and severity 'Critical'.

    **Validates: Requirements 7.2, 7.3**
    """
    func_name = f"{prefix}{keyword}{suffix}"
    source = _make_py_func_source(func_name)
    filepath = "agent/tools.py"

    findings = run({filepath: source})

    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    assert len(tool_findings) == 1, (
        f"Expected exactly 1 'Tool Permission Risk' finding for Python function "
        f"'{func_name}' (keyword='{keyword}'), got {len(tool_findings)}: "
        f"{tool_findings}"
    )

    finding = tool_findings[0]
    assert finding.severity == "Critical", (
        f"Expected severity 'Critical' for critical-tier keyword '{keyword}' "
        f"in function '{func_name}', got '{finding.severity}'"
    )
    assert finding.file == filepath, (
        f"Expected finding.file == '{filepath}', got '{finding.file}'"
    )


@given(
    keyword=st.sampled_from(_CRITICAL_KEYWORDS),
    prefix=_IDENT_FRAGMENT_ST,
    suffix=_IDENT_FRAGMENT_ST,
)
@settings(max_examples=200)
def test_critical_keyword_in_js_function_produces_one_critical_finding(
    keyword: str, prefix: str, suffix: str
) -> None:
    """
    Feature: adapt-backend-scanner, Property 9: Risky tool detection.

    For any JS function definition whose name contains a critical-tier keyword
    (case-insensitive), Tool_Scanner.run() SHALL produce exactly one Finding
    with category 'Tool Permission Risk' and severity 'Critical'.

    **Validates: Requirements 7.2, 7.3**
    """
    func_name = f"{prefix}{keyword}{suffix}"
    source = _make_js_func_source(func_name)
    filepath = "agent/tools.js"

    findings = run({filepath: source})

    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    assert len(tool_findings) == 1, (
        f"Expected exactly 1 'Tool Permission Risk' finding for JS function "
        f"'{func_name}' (keyword='{keyword}'), got {len(tool_findings)}: "
        f"{tool_findings}"
    )

    finding = tool_findings[0]
    assert finding.severity == "Critical", (
        f"Expected severity 'Critical' for critical-tier keyword '{keyword}' "
        f"in function '{func_name}', got '{finding.severity}'"
    )
    assert finding.file == filepath, (
        f"Expected finding.file == '{filepath}', got '{finding.file}'"
    )


def _fragment_has_no_critical_keyword(fragment: str) -> bool:
    """Return True if the fragment does not contain any critical-tier keyword."""
    lower = fragment.lower()
    return not any(kw in lower for kw in _CRITICAL_KEYWORDS)


# Fragments that are guaranteed to be free of critical-tier substrings so that
# wrapping a high-tier keyword with them doesn't accidentally elevate severity.
_SAFE_IDENT_FRAGMENT_ST = _IDENT_FRAGMENT_ST.filter(_fragment_has_no_critical_keyword)


@given(
    keyword=st.sampled_from(_HIGH_KEYWORDS),
    prefix=_SAFE_IDENT_FRAGMENT_ST,
    suffix=_SAFE_IDENT_FRAGMENT_ST,
)
@settings(max_examples=200)
def test_high_keyword_in_python_function_produces_one_high_finding(
    keyword: str, prefix: str, suffix: str
) -> None:
    """
    Feature: adapt-backend-scanner, Property 9: Risky tool detection.

    For any Python function definition whose name contains a high-tier keyword
    (case-insensitive) and no critical-tier keyword, Tool_Scanner.run() SHALL
    produce exactly one Finding with category 'Tool Permission Risk' and
    severity 'High'.

    **Validates: Requirements 7.2, 7.3**
    """
    func_name = f"{prefix}{keyword}{suffix}"
    source = _make_py_func_source(func_name)
    filepath = "agent/tools.py"

    findings = run({filepath: source})

    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    assert len(tool_findings) == 1, (
        f"Expected exactly 1 'Tool Permission Risk' finding for Python function "
        f"'{func_name}' (keyword='{keyword}'), got {len(tool_findings)}: "
        f"{tool_findings}"
    )

    finding = tool_findings[0]
    assert finding.severity == "High", (
        f"Expected severity 'High' for high-tier keyword '{keyword}' "
        f"in function '{func_name}', got '{finding.severity}'"
    )
    assert finding.file == filepath, (
        f"Expected finding.file == '{filepath}', got '{finding.file}'"
    )


@given(
    keyword=st.sampled_from(_HIGH_KEYWORDS),
    prefix=_SAFE_IDENT_FRAGMENT_ST,
    suffix=_SAFE_IDENT_FRAGMENT_ST,
)
@settings(max_examples=200)
def test_high_keyword_in_ts_function_produces_one_high_finding(
    keyword: str, prefix: str, suffix: str
) -> None:
    """
    Feature: adapt-backend-scanner, Property 9: Risky tool detection.

    For any TypeScript function definition whose name contains a high-tier
    keyword (case-insensitive) and no critical-tier keyword, Tool_Scanner.run()
    SHALL produce exactly one Finding with category 'Tool Permission Risk' and
    severity 'High'.

    **Validates: Requirements 7.2, 7.3**
    """
    func_name = f"{prefix}{keyword}{suffix}"
    source = _make_js_func_source(func_name)
    filepath = "agent/tools.ts"

    findings = run({filepath: source})

    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    assert len(tool_findings) == 1, (
        f"Expected exactly 1 'Tool Permission Risk' finding for TS function "
        f"'{func_name}' (keyword='{keyword}'), got {len(tool_findings)}: "
        f"{tool_findings}"
    )

    finding = tool_findings[0]
    assert finding.severity == "High", (
        f"Expected severity 'High' for high-tier keyword '{keyword}' "
        f"in function '{func_name}', got '{finding.severity}'"
    )
    assert finding.file == filepath, (
        f"Expected finding.file == '{filepath}', got '{finding.file}'"
    )


@given(
    critical_kw=st.sampled_from(_CRITICAL_KEYWORDS),
    high_kw=st.sampled_from(_HIGH_KEYWORDS),
)
@settings(max_examples=100)
def test_critical_takes_precedence_over_high_when_both_present_in_python(
    critical_kw: str, high_kw: str,
) -> None:
    """
    Feature: adapt-backend-scanner, Property 9: Risky tool detection.

    When a Python function name contains both a critical-tier and a high-tier
    keyword, Tool_Scanner.run() SHALL classify it as 'Critical' (critical tier
    takes precedence) and produce exactly one 'Tool Permission Risk' finding.

    **Validates: Requirements 7.2, 7.3**
    """
    func_name = f"{critical_kw}_{high_kw}"
    source = _make_py_func_source(func_name)
    filepath = "agent/tools.py"

    findings = run({filepath: source})

    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    assert len(tool_findings) == 1, (
        f"Expected exactly 1 'Tool Permission Risk' finding for Python function "
        f"'{func_name}' (critical='{critical_kw}', high='{high_kw}'), "
        f"got {len(tool_findings)}: {tool_findings}"
    )

    finding = tool_findings[0]
    assert finding.severity == "Critical", (
        f"Expected severity 'Critical' (critical tier should win) for function "
        f"'{func_name}', got '{finding.severity}'"
    )
