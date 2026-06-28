"""
Secret_Scanner — detects hardcoded secrets and prompt-injection exposure points.

Exposed interface:
    run(files: dict[str, str]) -> list[Finding]

Requirements: 6.1–6.6, 16.1–16.4
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Shared Finding dataclass (imported by all scanner modules)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str          # "Critical" | "High" | "Medium" | "Low" | "Info"
    category: str          # one of the six Risk_Categories
    file: str              # relative path
    line: int              # 1-based
    why_it_matters: str
    suggested_fix: str


# ---------------------------------------------------------------------------
# Secret detection patterns (Requirement 6.2, 6.4)
# ---------------------------------------------------------------------------

# High-criticality → Critical severity
CRITICAL_KEYWORDS: list[str] = [
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "AWS_ACCESS_KEY_ID",
    "FIREBASE_SERVICE_ACCOUNT",
    "FIREBASE_PRIVATE_KEY",
]

# Lower-criticality → High severity
HIGH_KEYWORDS: list[str] = [
    "DATABASE_URL",
    "JWT_SECRET",
    "SECRET_KEY",
    "API_KEY",
    "FIREBASE_API_KEY",
    "FIREBASE_PROJECT_ID",
    "FIREBASE_AUTH_DOMAIN",
]

# Value-prefix patterns → Critical severity
_CRITICAL_VALUE_PREFIXES = ("sk-", "AIza")

# All keyword patterns for quick line scanning
_ALL_KEYWORDS = CRITICAL_KEYWORDS + HIGH_KEYWORDS

# Matches:  KEYWORD  =  "non-empty-value"  (not os.getenv / os.environ)
# The negative lookahead prevents matching when the RHS is an env-read call.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?:^|[;\s])"""         # start of line or whitespace separator
    r"""({keyword})"""          # captured keyword
    r"""\s*=\s*"""              # assignment operator
    r"""(?!os\.getenv|os\.environ|getenv)"""   # NOT an env-read call
    r"""(?P<quote>["\'])"""     # opening quote
    r"""(?P<value>.+?)"""       # non-empty value (at least one char)
    r"""(?P=quote)""",          # matching closing quote
    re.IGNORECASE,
)

# Prompt injection: user-input variable names (Requirement 16.3)
_PROMPT_INJECTION_VARS = [
    "user_input",
    "user_message",
    "query",
    "prompt",
    "message",
    "request",
]

# Matches f-string interpolation:   f"...{var_name}..."
# or + concatenation:               "..." + var_name + "..."  /  var_name + "..."
_FSTRING_RE = re.compile(
    r"""f["\'].*\{""" + r"""(?:""" + "|".join(_PROMPT_INJECTION_VARS) + r""")""" + r"""\}.*["\']""",
    re.IGNORECASE,
)
_CONCAT_RE = re.compile(
    r"""(?:""" + "|".join(_PROMPT_INJECTION_VARS) + r""")\s*\+|"""
    r"""\+\s*(?:""" + "|".join(_PROMPT_INJECTION_VARS) + r""")""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_keyword(keyword: str, value: str) -> str | None:
    """Return severity string for a matched keyword+value, or None to skip."""
    kw_upper = keyword.upper()
    if kw_upper in [k.upper() for k in CRITICAL_KEYWORDS]:
        return "Critical"
    # Check value prefix for critical patterns (sk-, AIza)
    if any(value.startswith(prefix) for prefix in _CRITICAL_VALUE_PREFIXES):
        return "Critical"
    if kw_upper in [k.upper() for k in HIGH_KEYWORDS]:
        return "High"
    return None


def _scan_secrets_in_text(filepath: str, text: str) -> list[Finding]:
    """Scan file text for hardcoded secret assignments."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for keyword in _ALL_KEYWORDS:
            pattern = re.compile(
                r"""(?:^|[;\s])"""
                + re.escape(keyword)
                + r"""\s*=\s*"""
                r"""(?!os\.getenv|os\.environ|getenv)"""
                r"""(?P<quote>["\'])"""
                r"""(?P<value>.+?)"""
                r"""(?P=quote)""",
                re.IGNORECASE,
            )
            match = pattern.search(line)
            if match:
                value = match.group("value")
                severity = _classify_keyword(keyword, value)
                if severity is None:
                    continue
                findings.append(Finding(
                    title=f"Hardcoded {keyword.upper()} detected",
                    severity=severity,
                    category="Secret Exposure Risk",
                    file=filepath,
                    line=lineno,
                    why_it_matters=(
                        f"A hardcoded {keyword.upper()} in source code can be leaked "
                        "via version control, logs, or error messages, giving attackers "
                        "full access to the associated service."
                    ),
                    suggested_fix=(
                        f"Remove the hardcoded value. Load it at runtime via "
                        f"os.getenv('{keyword.upper()}') and store the real secret in "
                        "a .env file that is listed in .gitignore."
                    ),
                ))
                break  # one finding per line per keyword match

        # Check value-prefix patterns (sk-, AIza) that are not keyword-named
        for prefix in _CRITICAL_VALUE_PREFIXES:
            prefix_pattern = re.compile(
                r"""=\s*(?!os\.getenv|os\.environ|getenv)"""
                r"""(?P<quote>["\'])"""
                + re.escape(prefix)
                + r""".*?(?P=quote)""",
                re.IGNORECASE,
            )
            if prefix_pattern.search(line):
                # Only flag if no keyword was already matched on this line
                already_matched = any(
                    re.compile(
                        r"""(?:^|[;\s])""" + re.escape(kw) + r"""\s*=""",
                        re.IGNORECASE,
                    ).search(line)
                    for kw in _ALL_KEYWORDS
                )
                if not already_matched:
                    findings.append(Finding(
                        title=f"Hardcoded token with prefix '{prefix}' detected",
                        severity="Critical",
                        category="Secret Exposure Risk",
                        file=filepath,
                        line=lineno,
                        why_it_matters=(
                            f"Tokens starting with '{prefix}' are well-known API key "
                            "formats. Exposing them in source code allows attackers to "
                            "access the associated service."
                        ),
                        suggested_fix=(
                            "Remove the hardcoded token and load it at runtime via "
                            "an environment variable stored in a secure secret store."
                        ),
                    ))
                    break  # only one finding per prefix per line
    return findings


def _scan_prompt_injection_in_py(filepath: str, text: str) -> list[Finding]:
    """Scan .py file for direct user-input concatenation (Requirement 16.3)."""
    findings: list[Finding] = []
    lines = text.splitlines()
    # Detect direct returns or assignments of system prompt variables (under-detected case)
    _SYSTEM_PROMPT_VARS = [
        "system_prompt",
        "SYSTEM_PROMPT",
        "prompt_template",
        "base_prompt",
    ]
    _RETURN_SYSTEM_RE = re.compile(
        r"\breturn\s+(?:" + "|".join(re.escape(v) for v in _SYSTEM_PROMPT_VARS) + r")\b",
        re.IGNORECASE,
    )
    _ASSIGN_SYSTEM_RE = re.compile(
        r"\b(?:response|output|result|reply)\s*=\s*(?:" + "|".join(re.escape(v) for v in _SYSTEM_PROMPT_VARS) + r")\b",
        re.IGNORECASE,
    )
    for lineno, line in enumerate(lines, start=1):
        # Direct concatenation or f-string usage (user-input → prompt)
        if _FSTRING_RE.search(line) or _CONCAT_RE.search(line):
            findings.append(Finding(
                title="Direct user-input concatenation into string",
                severity="Medium",
                category="Prompt Injection Risk",
                file=filepath,
                line=lineno,
                why_it_matters=(
                    "Directly interpolating user-controlled variables into prompts "
                    "allows an attacker to inject malicious instructions into the LLM "
                    "context, potentially overriding the system prompt."
                ),
                suggested_fix=(
                    "Sanitise and validate user input before including it in prompts. "
                    "Use a structured message format (e.g. separate role/content dict) "
                    "rather than raw string concatenation."
                ),
            ))

        # Return or assignment of system prompt variables — high severity
        if _RETURN_SYSTEM_RE.search(line) or _ASSIGN_SYSTEM_RE.search(line):
            findings.append(Finding(
                title="System prompt exposed via return/assignment",
                severity="High",
                category="Prompt Injection Risk",
                file=filepath,
                line=lineno,
                why_it_matters=(
                    "Returning or assigning the system prompt variable directly exposes the agent's instructions. "
                    "This makes it trivial for adversaries to learn or manipulate system-level instructions, enabling prompt injection."
                ),
                suggested_fix=(
                    "Keep system prompts out of return values and avoid assigning them into outputs. "
                    "Load prompts server-side and never return or include them in agent responses."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run(files: dict[str, str]) -> list[Finding]:
    """
    Scan all provided files for hardcoded secrets and prompt-injection risks.

    Args:
        files: Mapping of relative file path → file text content.

    Returns:
        List of Finding objects (may be empty).
    """
    findings: list[Finding] = []

    for filepath, text in files.items():
        filename = os.path.basename(filepath).lower()
        _, ext = os.path.splitext(filename)

        # --- Requirement 6.3: .env file presence → High, Secret Exposure Risk ---
        if filename == ".env" or filepath.endswith(".env"):
            findings.append(Finding(
                title=".env file committed to project",
                severity="High",
                category="Secret Exposure Risk",
                file=filepath,
                line=1,
                why_it_matters=(
                    "A committed .env file exposes all environment variables — "
                    "including API keys, database credentials, and tokens — to anyone "
                    "with repository access."
                ),
                suggested_fix=(
                    "Add .env to .gitignore immediately. Rotate any secrets that may "
                    "have been committed. Use a secrets manager or CI/CD environment "
                    "variables instead."
                ),
            ))
            continue  # contents are irrelevant; one finding covers the whole file

        # --- Firebase Service Account JSON check ---
        if ext == ".json" and ("firebase" in filename or "serviceaccount" in filename):
            # Check if it looks like a Firebase service account key
            if '"private_key"' in text and '"project_id"' in text:
                findings.append(Finding(
                    title="Firebase Service Account key committed",
                    severity="Critical",
                    category="Secret Exposure Risk",
                    file=filepath,
                    line=1,
                    why_it_matters=(
                        "A Firebase service account JSON file provides full administrative "
                        "access to your Firebase project. Committing this to a repository "
                        "is a critical security risk."
                    ),
                    suggested_fix=(
                        "Remove the JSON file from the repository and add it to .gitignore. "
                        "Use environment variables or a secure secret manager to load "
                        "service account credentials at runtime. Rotate the key immediately "
                        "via the Google Cloud Console."
                    ),
                ))
                continue

        # --- Requirement 16.2: system_prompt*.txt → Medium, Prompt Injection Risk ---
        if ext == ".txt" and "system_prompt" in filename:
            findings.append(Finding(
                title="System prompt file committed to repository",
                severity="Medium",
                category="Prompt Injection Risk",
                file=filepath,
                line=1,
                why_it_matters=(
                    "A committed system prompt file reveals the agent's instructions "
                    "to anyone with repository access, making it trivial for attackers "
                    "to craft adversarial inputs that override or manipulate the prompt."
                ),
                suggested_fix=(
                    "Store the system prompt outside the repository (e.g. in a "
                    "database, secrets manager, or environment variable) and load it "
                    "at runtime. If it must be in the repo, treat its exposure as a "
                    "known risk and harden the prompt against injection."
                ),
            ))
            # fall through — also scan for secrets in the same file if needed

        # --- Requirement 6.2: hardcoded secret assignments ---
        if ext in {".py", ".js", ".jsx", ".ts", ".tsx", ".yml", ".yaml",
                   ".toml", ".txt", ".md", ".json"}:
            findings.extend(_scan_secrets_in_text(filepath, text))

        # --- Requirement 16.3: prompt injection via direct concatenation (Python only) ---
        if ext == ".py":
            findings.extend(_scan_prompt_injection_in_py(filepath, text))

    return findings
