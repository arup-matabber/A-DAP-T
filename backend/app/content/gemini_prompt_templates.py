"""
Gemini prompt templates for A-DAP-T.

The scanner remains rule-based. Gemini should only explain the final scan result
or help DAP answer questions from a provided report context.
"""


GEMINI_SYSTEM_INSTRUCTION = """
You are assisting A-DAP-T, a pre-deployment AI-agent risk scanner.

Rules:
- Do not invent findings that are not present in the scan result.
- Do not claim this is a full security audit.
- Do not claim the project is safe for production.
- Keep explanations specific to AI-agent deployment risks.
- No markdown headings, no tables, no long paragraphs.
- Keep answers short unless the user explicitly asks for more detail.
"""


def build_scan_summary_prompt(scan_result):
    return f"""
Write a compact scan summary.

Hard limits:
- 2 short sentences maximum.
- Mention safety score and risk status.
- Mention only the top 1-2 risk themes.
- No headings, bullets, tables, or markdown.

Scan result:
{scan_result}
"""


def build_finding_explanation_prompt(finding):
    return f"""
Explain this finding in developer-friendly language.

Hard limits:
- 3 short sentences maximum.
- Explain meaning, impact, and fix.
- No extra assumptions.

Finding:
{finding}
"""


def build_remediation_plan_prompt(scan_result):
    return f"""
Create a remediation plan.

Hard limits:
- Return exactly 5 concise bullets.
- Each bullet under 16 words.
- No headings, intro, outro, tables, or markdown.
- Prioritize Critical and High findings.

Scan result:
{scan_result}
"""


def build_report_summary_prompt(scan_result):
    return f"""
Create a short report summary.

Hard limits:
- 3 to 4 short lines maximum.
- Mention scanned project, score/status, main risks, and what to fix first.
- No headings, bullets, tables, markdown, or limitation notes.

Scan result:
{scan_result}
"""


def build_developer_next_steps_prompt(scan_result):
    return f"""
Write developer next steps.

Hard limits:
- Return exactly 5 concise bullets.
- Each bullet under 16 words.
- No headings, intro, outro, tables, or markdown.
- Focus on what to fix and retest.

Scan result:
{scan_result}
"""
