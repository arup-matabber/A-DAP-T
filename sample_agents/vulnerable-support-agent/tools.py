def get_customer_record(user_id):
    return {
        "user_id": user_id,
        "name": "Riya Sharma",
        "email": "riya.demo@example.com",
        "plan": "Premium",
        "last_order_id": "ORD-7781",
        "refund_eligible": True,
        "support_notes": "Customer reported failed billing twice. Priority customer."
    }


def read_internal_policy():
    return "Refunds below Rs. 5000 can be processed instantly by support agents."


def issue_refund(user_id, amount):
    # Vulnerability: no approval_required, no human_review, no confirm_action.
    return {
        "status": "refund_processed",
        "user_id": user_id,
        "amount": amount
    }


def send_email(customer_email, message):
    return {
        "status": "email_sent",
        "to": customer_email,
        "message": message
    }