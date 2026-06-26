import pytest
from app.graph import build_demo_graph, build_upload_graph
from app.scanners.secret_scanner import Finding

def test_build_demo_graph_vulnerable():
    graph = build_demo_graph("demo_vulnerable")
    node_ids = {n.id for n in graph["nodes"]}
    assert "user" in node_ids
    assert "agent" in node_ids
    assert "refund" in node_ids
    assert "customer_db" in node_ids
    assert "send_email" in node_ids

def test_build_demo_graph_secured():
    graph = build_demo_graph("demo_secured")
    node_ids = {n.id for n in graph["nodes"]}
    assert "user" in node_ids
    assert "agent" in node_ids
    assert "approval_gate" in node_ids
    assert "refund" in node_ids
    assert "audit_log" in node_ids

def test_build_upload_graph_vulnerable_tool():
    # A tool with both approval and audit findings (so no approval gate, no audit log)
    findings = [
        Finding(
            title="Risky function 'issue_refund' detected",
            severity="Critical",
            category="Tool Permission Risk",
            file="tools.py",
            line=10,
            why_it_matters="",
            suggested_fix=""
        ),
        Finding(
            title="No human approval gate found",
            severity="Critical",
            category="Human Approval Risk",
            file="tools.py",
            line=10,
            why_it_matters="",
            suggested_fix=""
        ),
        Finding(
            title="No audit logging found",
            severity="High",
            category="Auditability Risk",
            file="tools.py",
            line=10,
            why_it_matters="",
            suggested_fix=""
        )
    ]
    graph = build_upload_graph(findings)
    node_ids = {n.id for n in graph["nodes"]}
    assert "user" in node_ids
    assert "agent" in node_ids
    assert "issue_refund" in node_ids
    assert "approval_issue_refund" not in node_ids
    assert "audit_log" not in node_ids

    # There should be a direct edge from agent -> issue_refund
    edges = {(e.source, e.target, e.risk) for e in graph["edges"]}
    assert ("agent", "issue_refund", "critical") in edges

def test_build_upload_graph_secured_tool():
    # A tool with no approval or audit findings (so approval gate and audit log exist)
    findings = [
        Finding(
            title="Risky function 'issue_refund' detected",
            severity="Critical",
            category="Tool Permission Risk",
            file="tools.py",
            line=10,
            why_it_matters="",
            suggested_fix=""
        )
    ]
    graph = build_upload_graph(findings)
    node_ids = {n.id for n in graph["nodes"]}
    assert "user" in node_ids
    assert "agent" in node_ids
    assert "issue_refund" in node_ids
    assert "approval_issue_refund" in node_ids
    assert "audit_log" in node_ids

    # There should be:
    # agent -> approval_issue_refund (low risk)
    # approval_issue_refund -> issue_refund (critical risk)
    # issue_refund -> audit_log (low risk)
    edges = {(e.source, e.target, e.risk) for e in graph["edges"]}
    assert ("agent", "approval_issue_refund", "low") in edges
    assert ("approval_issue_refund", "issue_refund", "critical") in edges
    assert ("issue_refund", "audit_log", "low") in edges
