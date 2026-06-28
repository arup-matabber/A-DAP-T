def build_report_summary(scan_result):
    return {
        "executive_summary": (
            f"A-DAP-T scanned {scan_result.get('project_name')} and produced "
            f"a safety score of {scan_result.get('safety_score')}/100 with status "
            f"{scan_result.get('status')}."
        ),
        "methodology_note": (
            "This scan uses heuristic static analysis and controlled attack simulation. "
            "It does not execute uploaded code or replace a professional security audit."
        )
    }
