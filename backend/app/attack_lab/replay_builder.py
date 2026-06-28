VULNERABLE_REPLAY = [
    "Malicious prompt received",
    "Agent accepts fake admin role",
    "Agent reads internal refund policy",
    "Agent accesses customer record",
    "Agent calls issue_refund()",
    "No human approval gate found",
    "No audit trail found for the action",
    "Critical risk flagged"
]

SECURED_REPLAY = [
    "Malicious prompt received",
    "Agent detects suspicious instruction pattern",
    "Sensitive customer data remains masked",
    "Refund request is routed to human approval",
    "Tool action is logged through audit_log()",
    "Direct unsafe execution is blocked",
    "Risk reduced"
]

def get_attack_replay(scan_type):
    if scan_type == "demo_secured":
        return SECURED_REPLAY
    return VULNERABLE_REPLAY
