from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
BACKEND_DIR = CURRENT_FILE.parents[1]
REPO_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.scan_pipeline import build_scan_result  # noqa: E402


def _count(items) -> int:
    return len(items) if isinstance(items, list) else 0


def _gate_decision(report: dict) -> str:
    gate = report.get("deployment_gate") or {}
    return str(gate.get("decision") or "missing")


def build_demo_report(agent: str) -> dict:
    sample_dir = REPO_ROOT / "sample_agents" / agent
    if not sample_dir.exists():
        raise FileNotFoundError(f"Sample agent not found: {sample_dir}")

    scan_type = "demo_vulnerable" if "vulnerable" in agent else "demo_secured"
    return build_scan_result(
        str(sample_dir),
        project_name=agent,
        scan_type=scan_type,
        enrich=False,
    )


def assert_v2_contract(report: dict) -> None:
    required = ["findings", "attack_simulations", "patches", "deployment_gate", "score_delta"]
    missing = [key for key in required if key not in report]
    if missing:
        raise AssertionError(f"Missing V2 fields: {', '.join(missing)}")

    for key in ["attack_simulations", "patches"]:
        if not isinstance(report.get(key), list):
            raise AssertionError(f"{key} must be a list")

    gate = report.get("deployment_gate")
    if not isinstance(gate, dict):
        raise AssertionError("deployment_gate must be an object")

    for item in report.get("findings", []):
        if not item.get("id"):
            raise AssertionError("Every finding must include an id")

    finding_ids = {item.get("id") for item in report.get("findings", [])}
    for item in report.get("attack_simulations", []):
        if item.get("finding_id") not in finding_ids:
            raise AssertionError(f"Attack simulation is linked to unknown finding: {item.get('finding_id')}")
    for item in report.get("patches", []):
        if item.get("finding_id") not in finding_ids:
            raise AssertionError(f"Patch preview is linked to unknown finding: {item.get('finding_id')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test A-DAP-T V2 report artifacts.")
    parser.add_argument("--agent", default="vulnerable-support-agent", choices=["vulnerable-support-agent", "secured-support-agent"])
    parser.add_argument("--write-json", type=Path, help="Optional path to write the generated report JSON.")
    args = parser.parse_args()

    report = build_demo_report(args.agent)
    assert_v2_contract(report)

    summary = {
        "project_name": report.get("project_name"),
        "scan_type": report.get("scan_type"),
        "safety_score": report.get("safety_score"),
        "status": report.get("status"),
        "findings": _count(report.get("findings")),
        "attack_simulations": _count(report.get("attack_simulations")),
        "patches": _count(report.get("patches")),
        "deployment_gate": _gate_decision(report),
    }

    print(json.dumps(summary, indent=2))

    if args.write_json:
        args.write_json.parent.mkdir(parents=True, exist_ok=True)
        args.write_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote report JSON: {args.write_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
