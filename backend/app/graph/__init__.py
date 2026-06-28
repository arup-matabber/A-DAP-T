from __future__ import annotations
import re
from pydantic import BaseModel
from app.scanners.secret_scanner import Finding

class GraphNode(BaseModel):
    id: str
    label: str

class GraphEdge(BaseModel):
    source: str
    target: str
    risk: str

def build_demo_graph(scan_type: str) -> dict[str, list[GraphNode] | list[GraphEdge]]:
    """Build the demo graphs for vulnerable or secured runs."""
    if scan_type == "demo_vulnerable":
        nodes = [
            GraphNode(id="user", label="User Prompt"),
            GraphNode(id="agent", label="LLM Agent"),
            GraphNode(id="refund", label="issue_refund()"),
            GraphNode(id="customer_db", label="Customer Database"),
            GraphNode(id="send_email", label="send_email()")
        ]
        edges = [
            GraphEdge(source="user", target="agent", risk="medium"),
            GraphEdge(source="agent", target="refund", risk="critical"),
            GraphEdge(source="agent", target="customer_db", risk="high"),
            GraphEdge(source="agent", target="send_email", risk="high")
        ]
    else:  # demo_secured
        nodes = [
            GraphNode(id="user", label="User Prompt"),
            GraphNode(id="agent", label="LLM Agent"),
            GraphNode(id="approval_gate", label="Human Approval Gate"),
            GraphNode(id="refund", label="issue_refund()"),
            GraphNode(id="audit_log", label="Audit Log")
        ]
        edges = [
            GraphEdge(source="user", target="agent", risk="medium"),
            GraphEdge(source="agent", target="approval_gate", risk="low"),
            GraphEdge(source="approval_gate", target="refund", risk="medium"),
            GraphEdge(source="refund", target="audit_log", risk="low")
        ]
    return {"nodes": nodes, "edges": edges}

def _extract_func_name(title: str) -> str:
    """Extract the function name from the tool scanner finding title."""
    m = re.search(r"Risky function '([^']+)' detected", title)
    if m:
        return m.group(1)
    return title.replace(" ", "_").lower()

def build_upload_graph(findings: list[Finding]) -> dict[str, list[GraphNode] | list[GraphEdge]]:
    """
    Generate graph nodes and edges dynamically from detected findings.
    Specifically connects agent node to risky tools, introducing approval gates
    and audit logs where they are resolved.
    """
    # 1. Check for prompt injection findings to determine user-to-agent risk
    user_agent_risk = "low"
    for f in findings:
        if f.category == "Prompt Injection Risk":
            if f.severity.lower() == "critical":
                user_agent_risk = "critical"
            elif f.severity.lower() == "high" and user_agent_risk != "critical":
                user_agent_risk = "high"
            elif f.severity.lower() == "medium" and user_agent_risk not in ("critical", "high"):
                user_agent_risk = "medium"

    nodes = [
        GraphNode(id="user", label="User Prompt"),
        GraphNode(id="agent", label="LLM Agent")
    ]
    edges = [
        GraphEdge(source="user", target="agent", risk=user_agent_risk)
    ]

    # Filter tool permission risk findings
    tool_findings = [f for f in findings if f.category == "Tool Permission Risk"]

    added_nodes = {"user", "agent"}

    for tf in tool_findings:
        func_name = _extract_func_name(tf.title)
        tool_id = func_name
        tool_label = f"{func_name}()"
        tool_risk = tf.severity.lower()

        # Add tool node
        if tool_id not in added_nodes:
            nodes.append(GraphNode(id=tool_id, label=tool_label))
            added_nodes.add(tool_id)

        # Check if approval risk exists for this specific tool finding
        has_approval_risk = any(
            f.category == "Human Approval Risk" and f.file == tf.file and f.line == tf.line
            for f in findings
        )

        # Check if audit risk exists for this specific tool finding
        has_audit_risk = any(
            f.category == "Auditability Risk" and f.file == tf.file and f.line == tf.line
            for f in findings
        )

        # Connect agent to tool (via approval gate if secured)
        if not has_approval_risk:
            # Approval gate exists
            gate_id = f"approval_{func_name}"
            gate_label = f"Approval Gate: {func_name}"
            if gate_id not in added_nodes:
                nodes.append(GraphNode(id=gate_id, label=gate_label))
                added_nodes.add(gate_id)
            edges.append(GraphEdge(source="agent", target=gate_id, risk="low"))
            edges.append(GraphEdge(source=gate_id, target=tool_id, risk=tool_risk))
        else:
            # Direct connection (vulnerable)
            edges.append(GraphEdge(source="agent", target=tool_id, risk=tool_risk))

        # Connect tool to audit log if audited
        if not has_audit_risk:
            audit_id = "audit_log"
            audit_label = "Audit Log"
            if audit_id not in added_nodes:
                nodes.append(GraphNode(id=audit_id, label=audit_label))
                added_nodes.add(audit_id)
            edges.append(GraphEdge(source=tool_id, target=audit_id, risk="low"))

    return {"nodes": nodes, "edges": edges}
