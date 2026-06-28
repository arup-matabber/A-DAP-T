from __future__ import annotations

import json
from typing import Any

DEFAULT_POLICY = {
    "minimum_safety_score": 75,
    "block_on_critical": True,
    "block_on_secrets": True,
    "block_on_missing_approval": True,
    "block_on_unsafe_tools": True,
}


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _has_category(findings: list[dict], text: str) -> bool:
    needle = text.lower()
    return any(needle in _lower(finding.get("category")) for finding in findings)


def _severity_rank(value: Any) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(_lower(value), 0)


def _has_category_at_or_above(findings: list[dict], text: str, minimum_severity: str = "high") -> bool:
    needle = text.lower()
    threshold = _severity_rank(minimum_severity)
    return any(
        needle in _lower(finding.get("category"))
        and _severity_rank(finding.get("severity")) >= threshold
        for finding in findings
    )


def _count_category_at_or_above(findings: list[dict], text: str, minimum_severity: str = "high") -> int:
    needle = text.lower()
    threshold = _severity_rank(minimum_severity)
    return sum(
        1
        for finding in findings
        if needle in _lower(finding.get("category"))
        and _severity_rank(finding.get("severity")) >= threshold
    )


def _has_severity(findings: list[dict], severity: str) -> bool:
    target = severity.lower()
    return any(_lower(finding.get("severity")) == target for finding in findings)


def _severity_count(findings: list[dict], severity: str) -> int:
    target = severity.lower()
    return sum(1 for finding in findings if _lower(finding.get("severity")) == target)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    return {
        "critical": _severity_count(findings, "critical"),
        "high": _severity_count(findings, "high"),
        "medium": _severity_count(findings, "medium"),
        "low": _severity_count(findings, "low"),
    }


def _gate_score(safety_score: int, blockers: list[str], findings: list[dict]) -> int:
    penalty = min(len(blockers) * 8, 32)
    if _has_severity(findings, "critical"):
        penalty += 10
    return max(0, min(100, safety_score - penalty))


def _decision_badge(decision: str) -> str:
    return {
        "BLOCK": "Blocked before deployment",
        "REVIEW": "Manual review required",
        "ALLOW": "Ready under current policy",
    }.get(decision, "Unknown gate decision")


def _next_actions(decision: str, blockers: list[str]) -> list[str]:
    if decision == "BLOCK":
        actions = ["Fix the listed blockers before release.", "Re-run the scan after applying patches."]
        if any("secret" in item.lower() for item in blockers):
            actions.insert(0, "Rotate exposed secrets before deploying again.")
        if any("approval" in item.lower() for item in blockers):
            actions.append("Verify high-impact tools fail closed without approval.")
        if any("tool" in item.lower() for item in blockers):
            actions.append("Scope risky tools to least privilege and add audit logging.")
        return actions[:5]
    if decision == "REVIEW":
        return [
            "Review remaining medium/high findings.",
            "Document accepted risk before release.",
            "Re-scan after any final remediation.",
        ]
    return [
        "Proceed with normal release checks.",
        "Keep A-DAP-T in CI to catch future agent-risk regressions.",
    ]


def _download_assets(policy: dict) -> list[dict]:
    return [
        {
            "kind": "github_actions_workflow",
            "filename": "adapt-agent-safety-gate.yml",
            "label": "Download GitHub Actions workflow",
            "content_type": "text/yaml",
        },
        {
            "kind": "deployment_policy",
            "filename": "adapt-policy.json",
            "label": "Download deployment policy",
            "content_type": "application/json",
        },
    ]


def _ci_secret_requirements() -> list[dict]:
    return [
        {"name": "ADAPT_API_URL", "purpose": "Base URL of the deployed A-DAP-T backend"},
        {"name": "ADAPT_ID_TOKEN", "purpose": "Firebase ID token or CI service token used to call protected scan endpoints"},
    ]


def _category_blockers(findings: list[dict]) -> dict[str, int]:
    return {
        "secret_exposure": sum(1 for finding in findings if "secret exposure" in _lower(finding.get("category"))),
        "human_approval": _count_category_at_or_above(findings, "human approval", "high"),
        "tool_permission": _count_category_at_or_above(findings, "tool permission", "high"),
    }


def _github_actions_yaml(policy: dict) -> str:
    minimum = int(policy.get("minimum_safety_score", 75))
    block_critical = str(bool(policy.get("block_on_critical", True))).lower()
    block_secrets = str(bool(policy.get("block_on_secrets", True))).lower()
    block_approval = str(bool(policy.get("block_on_missing_approval", True))).lower()
    block_tools = str(bool(policy.get("block_on_unsafe_tools", True))).lower()

    return f"""name: A-DAP-T Agent Safety Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  adapt-safety-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Build repository scan URL
        id: repo
        run: |
          echo "repo_url=https://github.com/${{{{ github.repository }}}}" >> "$GITHUB_OUTPUT"

      - name: Run A-DAP-T scan
        env:
          ADAPT_API_URL: ${{{{ secrets.ADAPT_API_URL }}}}
          ADAPT_ID_TOKEN: ${{{{ secrets.ADAPT_ID_TOKEN }}}}
          REPO_URL: ${{{{ steps.repo.outputs.repo_url }}}}
        run: |
          test -n "$ADAPT_API_URL" || (echo "Missing ADAPT_API_URL secret" && exit 1)
          test -n "$ADAPT_ID_TOKEN" || (echo "Missing ADAPT_ID_TOKEN secret" && exit 1)

          curl -sS -X POST "$ADAPT_API_URL/scan/github" \\
            -H "Authorization: Bearer $ADAPT_ID_TOKEN" \\
            -H "Content-Type: application/json" \\
            -d "{{\"repo_url\":\"$REPO_URL\",\"branch\":\"${{{{ github.ref_name }}}}\",\"save_report\":false}}" \\
            -o adapt-report.json

          cat adapt-report.json

      - name: Enforce A-DAP-T policy
        env:
          MINIMUM_SAFETY_SCORE: "{minimum}"
          BLOCK_ON_CRITICAL: "{block_critical}"
          BLOCK_ON_SECRETS: "{block_secrets}"
          BLOCK_ON_MISSING_APPROVAL: "{block_approval}"
          BLOCK_ON_UNSAFE_TOOLS: "{block_tools}"
        run: |
          python - <<'PY'
          import json, os, sys

          with open('adapt-report.json', 'r', encoding='utf-8') as f:
              report = json.load(f)

          score = int(report.get('safety_score') or 0)
          findings = report.get('findings') or []
          minimum = int(os.environ['MINIMUM_SAFETY_SCORE'])

          blockers = []
          if score < minimum:
              blockers.append(f"Safety score {{score}} is below required minimum {{minimum}}")

          def enabled(name):
              return os.environ.get(name, '').lower() == 'true'

          def has_severity(level):
              return any(str(f.get('severity', '')).lower() == level for f in findings)

          def severity_rank(value):
              return {{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}}.get(str(value or '').lower(), 0)

          def has_category(text, minimum_severity=None):
              for f in findings:
                  if text not in str(f.get('category', '')).lower():
                      continue
                  if minimum_severity and severity_rank(f.get('severity')) < severity_rank(minimum_severity):
                      continue
                  return True
              return False

          if enabled('BLOCK_ON_CRITICAL') and has_severity('critical'):
              blockers.append('Critical findings are present')
          if enabled('BLOCK_ON_SECRETS') and has_category('secret exposure'):
              blockers.append('Secret exposure risk detected')
          if enabled('BLOCK_ON_MISSING_APPROVAL') and has_category('human approval', 'high'):
              blockers.append('High-risk missing approval gate detected')
          if enabled('BLOCK_ON_UNSAFE_TOOLS') and has_category('tool permission', 'high'):
              blockers.append('High-risk unsafe tool permission detected')

          if blockers:
              print('A-DAP-T deployment gate: BLOCK')
              for item in blockers:
                  print(f'- {{item}}')
              sys.exit(1)

          print('A-DAP-T deployment gate: PASS')
          PY

      - name: Upload A-DAP-T report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: adapt-report
          path: adapt-report.json
""".strip()


def _decision_summary(decision: str, blockers: list[str], safety_score: int, minimum: int) -> str:
    if decision == "BLOCK":
        return f"Deployment should be blocked. Safety score is {safety_score}/{minimum} threshold and {len(blockers)} blocker(s) were found."
    if decision == "REVIEW":
        return "Deployment should wait for manual review. No hard blocker was found, but unresolved medium/high risk remains."
    return "Deployment can proceed under the current policy. No configured blocker was found."


def build_deployment_gate(scan_result: dict, policy: dict | None = None) -> dict:
    active_policy = {**DEFAULT_POLICY, **(policy or {})}
    findings = scan_result.get("findings") or []
    safety_score = int(scan_result.get("safety_score") or 0)
    minimum = int(active_policy.get("minimum_safety_score", 75))
    blockers: list[str] = []

    if safety_score < minimum:
        blockers.append(f"Safety score is below {minimum}.")
    if active_policy.get("block_on_critical") and _has_severity(findings, "critical"):
        blockers.append(f"Critical findings are present ({_severity_count(findings, 'critical')}).")
    if active_policy.get("block_on_secrets") and _has_category(findings, "secret exposure"):
        blockers.append("Secret exposure risk detected.")
    if active_policy.get("block_on_missing_approval") and _has_category_at_or_above(findings, "human approval", "high"):
        blockers.append("High-risk missing human approval gate detected.")
    if active_policy.get("block_on_unsafe_tools") and _has_category_at_or_above(findings, "tool permission", "high"):
        blockers.append("High-risk unsafe or overly broad tool permission detected.")

    has_high_or_medium = any(_lower(f.get("severity")) in {"high", "medium"} for f in findings)
    if blockers:
        decision = "BLOCK"
        required_action = "Fix blockers and re-scan before deployment."
    elif has_high_or_medium:
        decision = "REVIEW"
        required_action = "Review remaining findings and accept risk explicitly before deployment."
    else:
        decision = "ALLOW"
        required_action = "Proceed, while keeping normal monitoring and release checks in place."

    category_counts = _category_blockers(findings)
    policy_json = json.dumps(
        {
            "policy": active_policy,
            "decision": decision,
            "minimum_safety_score": minimum,
            "blockers": blockers,
            "category_blocker_counts": category_counts,
        },
        indent=2,
    )

    severity_counts = _severity_counts(findings)
    gate_score = _gate_score(safety_score, blockers, findings)
    summary = _decision_summary(decision, blockers, safety_score, minimum)

    return {
        "decision": decision,
        "decision_badge": _decision_badge(decision),
        "minimum_safety_score": minimum,
        "safety_score": safety_score,
        "gate_score": gate_score,
        "blockers": blockers,
        "recommended_policy": active_policy,
        "github_actions_yaml": _github_actions_yaml(active_policy),
        "policy_json": policy_json,
        "summary": summary,
        "decision_reason": blockers[0] if blockers else summary,
        "required_action": required_action,
        "next_actions": _next_actions(decision, blockers),
        "workflow_filename": "adapt-agent-safety-gate.yml",
        "policy_filename": "adapt-policy.json",
        "download_assets": _download_assets(active_policy),
        "ci_secret_requirements": _ci_secret_requirements(),
        "category_blocker_counts": category_counts,
        "severity_counts": severity_counts,
    }
