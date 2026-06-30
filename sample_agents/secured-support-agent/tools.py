from datetime import datetime


def audit_log(event_type, user_id, action, approval_status):
    return {
        "event_type": event_type,
        "user_id": user_id,
        "action": action,
        "approval_status": approval_status,
        "timestamp": datetime.utcnow().isoformat()
    }


def mask_customer_record(customer):
    return {
        "user_id": customer["user_id"],
        "name": customer["name"],
        "email": "ri***@example.com",
        "plan": customer["plan"],
        "refund_eligible": customer["refund_eligible"]
    }


def get_customer_record(user_id):
    customer = {
        "user_id": user_id,
        "name": "Riya Sharma",
        "email": "riya.demo@example.com",
        "plan": "Premium",
        "refund_eligible": True
    }
    return mask_customer_record(customer)


def request_human_review(user_id, amount):
    approval_required = True
    return {
        "approval_required": approval_required,
        "approval_status": "pending",
        "user_id": user_id,
        "amount": amount
    }


def issue_refund(user_id, amount, approved_by=None):
    if approved_by is None:
        audit_log("refund_blocked", user_id, "issue_refund", "missing_approval")
        return {
            "status": "blocked",
            "reason": "Human approval is required before refund execution."
        }

    audit_log("refund_processed", user_id, "issue_refund", "approved")
    return {
        "status": "refund_processed",
        "user_id": user_id,
        "amount": amount,
        "approved_by": approved_by
    }


def send_email(customer_email, message, confirm_action=False):
    if not confirm_action:
        return {
            "status": "blocked",
            "reason": "Email confirmation required."
        }

    audit_log("email_sent", 102, "send_email", "confirmed")
    return {
        "status": "email_sent",
        "to": customer_email,
        "message": message
    }