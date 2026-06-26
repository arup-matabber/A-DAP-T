"""
Property-based tests for Secret_Scanner.

Tests are tagged with the property number defined in design.md for traceability.
"""

from hypothesis import given, settings, strategies as st

from app.scanners.secret_scanner import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_system_prompt_txt_name(stem: str, casing_map: list[bool]) -> str:
    """
    Build a filename like '<stem>system_prompt<suffix>.txt' with the
    substring 'system_prompt' rewritten according to casing_map.

    casing_map is a list of booleans (one per character in 'system_prompt');
    True means uppercase, False means lowercase.
    """
    base = "system_prompt"
    # Apply casing
    cased_chars = []
    for i, ch in enumerate(base):
        use_upper = casing_map[i] if i < len(casing_map) else False
        cased_chars.append(ch.upper() if use_upper else ch.lower())
    cased = "".join(cased_chars)
    # Produce a safe stem (may be empty → just use the keyword)
    safe_stem = stem if stem else ""
    return f"{safe_stem}{cased}.txt"


# ---------------------------------------------------------------------------
# Feature: adapt-backend-scanner
# Property 15: Prompt injection system-prompt file detection
# Validates: Requirements 16.2
# ---------------------------------------------------------------------------

# Strategy: generate a boolean list of length 13 (len("system_prompt"))
# that drives per-character casing, plus an optional stem prefix.
_CASING_ST = st.lists(st.booleans(), min_size=13, max_size=13)
_STEM_ST = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="_-",
    ),
    min_size=0,
    max_size=20,
)


@given(stem=_STEM_ST, casing_map=_CASING_ST)
@settings(max_examples=200)
def test_system_prompt_file_detection_exactly_one_finding(
    stem: str, casing_map: list[bool]
) -> None:
    """
    Feature: adapt-backend-scanner, Property 15: Prompt injection system-prompt
    file detection.

    For any .txt filename whose basename contains 'system_prompt'
    (case-insensitive), Secret_Scanner.run() SHALL produce exactly one
    Finding with category 'Prompt Injection Risk' for that file.

    Validates: Requirements 16.2
    """
    filename = _make_system_prompt_txt_name(stem, casing_map)

    # The file content is irrelevant for this heuristic — use empty string
    files = {filename: ""}

    findings = run(files)

    prompt_injection_findings = [
        f for f in findings if f.category == "Prompt Injection Risk"
    ]

    assert len(prompt_injection_findings) == 1, (
        f"Expected exactly 1 'Prompt Injection Risk' finding for file "
        f"'{filename}', got {len(prompt_injection_findings)}: "
        f"{prompt_injection_findings}"
    )

    finding = prompt_injection_findings[0]
    assert finding.severity == "Medium", (
        f"Expected severity 'Medium', got '{finding.severity}' for file "
        f"'{filename}'"
    )
    assert finding.file == filename, (
        f"Expected finding.file == '{filename}', got '{finding.file}'"
    )
