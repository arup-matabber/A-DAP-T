REMEDIATION_TEMPLATES = {
    "Secret Exposure Risk": {
        "why_it_matters": "Exposed API keys and secrets can allow unauthorized access to models, databases, or internal services.",
        "suggested_fix": "Move secrets to environment variables and keep .env files out of Git.",
        "example_fix": "Use os.getenv('GEMINI_API_KEY') instead of hardcoding the key in config.py."
    },
    "Tool Permission Risk": {
        "why_it_matters": "The model may trigger high-impact tools directly from user-controlled input.",
        "suggested_fix": "Restrict dangerous tools and require explicit confirmation before execution.",
        "example_fix": "Block issue_refund(), send_email(), delete_user(), or payment functions unless approval status is verified."
    },
    "Human Approval Risk": {
        "why_it_matters": "High-impact actions such as refunds, payments, deletes, and admin changes should not be executed without human review.",
        "suggested_fix": "Add a human approval checkpoint before executing risky tools.",
        "example_fix": "Route refund requests to request_human_review() before calling issue_refund()."
    },
    "Auditability Risk": {
        "why_it_matters": "Without audit logs, teams cannot investigate what action the agent performed, when it happened, or why it happened.",
        "suggested_fix": "Log tool name, input parameters, user/session ID, approval status, timestamp, and result.",
        "example_fix": "Call audit_log() before and after risky tool execution."
    },
    "Data Exposure Risk": {
        "why_it_matters": "AI agents may expose customer records, support notes, emails, or internal data if access is not restricted.",
        "suggested_fix": "Mask sensitive fields and return only the minimum data required for the task.",
        "example_fix": "Return ri***@example.com instead of the full customer email address."
    },
    "Prompt Injection Risk": {
        "why_it_matters": "Malicious prompts can attempt to override system instructions, reveal hidden policies, or trigger unsafe tool calls.",
        "suggested_fix": "Detect suspicious instruction patterns and separate untrusted user input from privileged tool execution.",
        "example_fix": "Block prompts containing phrases like 'ignore previous instructions' or route them to review."
    }
}

def get_remediation_for_category(category):
    return REMEDIATION_TEMPLATES.get(category, {
        "why_it_matters": "This issue may increase AI-agent deployment risk.",
        "suggested_fix": "Review the affected file and add safer validation, approval, or logging controls.",
        "example_fix": "Add explicit checks before allowing model-controlled actions."
    })
