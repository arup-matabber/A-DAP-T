"""
Unit tests for scan_schema.py Pydantic models.
Covers Requirements 12.1, 12.2, 12.3, 12.4, 12.5
"""
import pytest
from pydantic import ValidationError

from app.schemas.scan_schema import (
    FindingSchema,
    CategoryScoresSchema,
    SummarySchema,
    GraphNodeSchema,
    GraphEdgeSchema,
    GraphSchema,
    ScanResultSchema,
)


# ---------------------------------------------------------------------------
# Helpers — minimal valid payloads for each schema
# ---------------------------------------------------------------------------

VALID_FINDING = {
    "title": "Hardcoded API key detected",
    "severity": "Critical",
    "category": "Secret Exposure Risk",
    "file": "agent.py",
    "line": 12,
    "why_it_matters": "Exposed keys can be stolen.",
    "suggested_fix": "Use environment variables instead.",
}

VALID_CATEGORY_SCORES = {
    "prompt_injection": 0,
    "secret_exposure": 40,
    "tool_permission": 25,
    "human_approval": 10,
    "data_exposure": 5,
    "auditability": 15,
}

VALID_SUMMARY = {"critical": 2, "high": 3, "medium": 1, "low": 0}

VALID_GRAPH_NODE = {"id": "agent", "label": "Agent"}

VALID_GRAPH_EDGE = {"source": "agent", "target": "refund", "risk": "critical"}

VALID_GRAPH = {
    "nodes": [VALID_GRAPH_NODE, {"id": "refund", "label": "Refund"}],
    "edges": [VALID_GRAPH_EDGE],
}

VALID_SCAN_RESULT = {
    "project_name": "vulnerable-support-agent",
    "scan_type": "demo_vulnerable",
    "safety_score": 42,
    "status": "High Risk",
    "summary": VALID_SUMMARY,
    "category_scores": VALID_CATEGORY_SCORES,
    "findings": [VALID_FINDING],
    "graph": VALID_GRAPH,
    "attack_replay": ["Step 1: inject prompt", "Step 2: exfiltrate data"],
    "remediation_checklist": ["Rotate API keys", "Add approval gates"],
}


# ---------------------------------------------------------------------------
# FindingSchema — Requirement 12.1
# ---------------------------------------------------------------------------

class TestFindingSchema:
    def test_valid_finding_serialises(self):
        finding = FindingSchema(**VALID_FINDING)
        assert finding.title == "Hardcoded API key detected"
        assert finding.severity == "Critical"
        assert finding.category == "Secret Exposure Risk"
        assert finding.file == "agent.py"
        assert finding.line == 12
        assert finding.why_it_matters == "Exposed keys can be stolen."
        assert finding.suggested_fix == "Use environment variables instead."

    def test_finding_model_dump_round_trip(self):
        finding = FindingSchema(**VALID_FINDING)
        dumped = finding.model_dump()
        restored = FindingSchema(**dumped)
        assert restored == finding

    def test_finding_missing_title_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "title"}
        with pytest.raises(ValidationError) as exc_info:
            FindingSchema(**data)
        assert "title" in str(exc_info.value)

    def test_finding_missing_severity_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "severity"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_missing_category_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "category"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_missing_file_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "file"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_missing_line_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "line"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_missing_why_it_matters_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "why_it_matters"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_missing_suggested_fix_raises(self):
        data = {k: v for k, v in VALID_FINDING.items() if k != "suggested_fix"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)

    def test_finding_line_must_be_int(self):
        data = {**VALID_FINDING, "line": "not_an_int"}
        with pytest.raises(ValidationError):
            FindingSchema(**data)


# ---------------------------------------------------------------------------
# CategoryScoresSchema — Requirement 12.2
# ---------------------------------------------------------------------------

class TestCategoryScoresSchema:
    def test_valid_category_scores_serialises(self):
        scores = CategoryScoresSchema(**VALID_CATEGORY_SCORES)
        assert scores.prompt_injection == 0
        assert scores.secret_exposure == 40
        assert scores.tool_permission == 25
        assert scores.human_approval == 10
        assert scores.data_exposure == 5
        assert scores.auditability == 15

    def test_category_scores_round_trip(self):
        scores = CategoryScoresSchema(**VALID_CATEGORY_SCORES)
        restored = CategoryScoresSchema(**scores.model_dump())
        assert restored == scores

    def test_missing_prompt_injection_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "prompt_injection"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_missing_secret_exposure_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "secret_exposure"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_missing_tool_permission_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "tool_permission"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_missing_human_approval_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "human_approval"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_missing_data_exposure_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "data_exposure"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_missing_auditability_raises(self):
        data = {k: v for k, v in VALID_CATEGORY_SCORES.items() if k != "auditability"}
        with pytest.raises(ValidationError):
            CategoryScoresSchema(**data)

    def test_all_zeros_valid(self):
        scores = CategoryScoresSchema(
            prompt_injection=0, secret_exposure=0,
            tool_permission=0, human_approval=0,
            data_exposure=0, auditability=0,
        )
        assert scores.model_dump() == {
            "prompt_injection": 0, "secret_exposure": 0,
            "tool_permission": 0, "human_approval": 0,
            "data_exposure": 0, "auditability": 0,
        }


# ---------------------------------------------------------------------------
# SummarySchema — Requirement 12.3
# ---------------------------------------------------------------------------

class TestSummarySchema:
    def test_valid_summary_serialises(self):
        summary = SummarySchema(**VALID_SUMMARY)
        assert summary.critical == 2
        assert summary.high == 3
        assert summary.medium == 1
        assert summary.low == 0

    def test_summary_round_trip(self):
        summary = SummarySchema(**VALID_SUMMARY)
        restored = SummarySchema(**summary.model_dump())
        assert restored == summary

    def test_missing_critical_raises(self):
        data = {k: v for k, v in VALID_SUMMARY.items() if k != "critical"}
        with pytest.raises(ValidationError):
            SummarySchema(**data)

    def test_missing_high_raises(self):
        data = {k: v for k, v in VALID_SUMMARY.items() if k != "high"}
        with pytest.raises(ValidationError):
            SummarySchema(**data)

    def test_missing_medium_raises(self):
        data = {k: v for k, v in VALID_SUMMARY.items() if k != "medium"}
        with pytest.raises(ValidationError):
            SummarySchema(**data)

    def test_missing_low_raises(self):
        data = {k: v for k, v in VALID_SUMMARY.items() if k != "low"}
        with pytest.raises(ValidationError):
            SummarySchema(**data)


# ---------------------------------------------------------------------------
# GraphNodeSchema — Requirement 12.4
# ---------------------------------------------------------------------------

class TestGraphNodeSchema:
    def test_valid_node_serialises(self):
        node = GraphNodeSchema(**VALID_GRAPH_NODE)
        assert node.id == "agent"
        assert node.label == "Agent"

    def test_node_round_trip(self):
        node = GraphNodeSchema(**VALID_GRAPH_NODE)
        restored = GraphNodeSchema(**node.model_dump())
        assert restored == node

    def test_missing_id_raises(self):
        with pytest.raises(ValidationError):
            GraphNodeSchema(label="Agent")

    def test_missing_label_raises(self):
        with pytest.raises(ValidationError):
            GraphNodeSchema(id="agent")


# ---------------------------------------------------------------------------
# GraphEdgeSchema — Requirement 12.4
# ---------------------------------------------------------------------------

class TestGraphEdgeSchema:
    def test_valid_edge_serialises(self):
        edge = GraphEdgeSchema(**VALID_GRAPH_EDGE)
        assert edge.source == "agent"
        assert edge.target == "refund"
        assert edge.risk == "critical"

    def test_edge_round_trip(self):
        edge = GraphEdgeSchema(**VALID_GRAPH_EDGE)
        restored = GraphEdgeSchema(**edge.model_dump())
        assert restored == edge

    def test_missing_source_raises(self):
        data = {k: v for k, v in VALID_GRAPH_EDGE.items() if k != "source"}
        with pytest.raises(ValidationError):
            GraphEdgeSchema(**data)

    def test_missing_target_raises(self):
        data = {k: v for k, v in VALID_GRAPH_EDGE.items() if k != "target"}
        with pytest.raises(ValidationError):
            GraphEdgeSchema(**data)

    def test_missing_risk_raises(self):
        data = {k: v for k, v in VALID_GRAPH_EDGE.items() if k != "risk"}
        with pytest.raises(ValidationError):
            GraphEdgeSchema(**data)


# ---------------------------------------------------------------------------
# GraphSchema — Requirement 12.4
# ---------------------------------------------------------------------------

class TestGraphSchema:
    def test_valid_graph_serialises(self):
        graph = GraphSchema(**VALID_GRAPH)
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert graph.nodes[0].id == "agent"
        assert graph.edges[0].risk == "critical"

    def test_graph_round_trip(self):
        graph = GraphSchema(**VALID_GRAPH)
        restored = GraphSchema(**graph.model_dump())
        assert restored == graph

    def test_graph_empty_nodes_and_edges_valid(self):
        graph = GraphSchema(nodes=[], edges=[])
        assert graph.nodes == []
        assert graph.edges == []

    def test_missing_nodes_raises(self):
        with pytest.raises(ValidationError):
            GraphSchema(edges=[])

    def test_missing_edges_raises(self):
        with pytest.raises(ValidationError):
            GraphSchema(nodes=[])


# ---------------------------------------------------------------------------
# ScanResultSchema — Requirement 12.5
# ---------------------------------------------------------------------------

class TestScanResultSchema:
    def test_valid_scan_result_serialises(self):
        result = ScanResultSchema(**VALID_SCAN_RESULT)
        assert result.project_name == "vulnerable-support-agent"
        assert result.scan_type == "demo_vulnerable"
        assert result.safety_score == 42
        assert result.status == "High Risk"
        assert len(result.findings) == 1
        assert len(result.attack_replay) == 2
        assert len(result.remediation_checklist) == 2

    def test_scan_result_round_trip(self):
        """Full round-trip: serialise to dict then reconstruct."""
        result = ScanResultSchema(**VALID_SCAN_RESULT)
        dumped = result.model_dump()
        restored = ScanResultSchema(**dumped)
        assert restored == result

    def test_scan_result_empty_findings_valid(self):
        data = {**VALID_SCAN_RESULT, "findings": []}
        result = ScanResultSchema(**data)
        assert result.findings == []

    def test_scan_result_empty_attack_replay_valid(self):
        data = {**VALID_SCAN_RESULT, "attack_replay": []}
        result = ScanResultSchema(**data)
        assert result.attack_replay == []

    def test_scan_result_empty_remediation_checklist_valid(self):
        data = {**VALID_SCAN_RESULT, "remediation_checklist": []}
        result = ScanResultSchema(**data)
        assert result.remediation_checklist == []

    def test_missing_project_name_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "project_name"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_scan_type_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "scan_type"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_safety_score_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "safety_score"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_status_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "status"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_summary_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "summary"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_category_scores_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "category_scores"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_findings_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "findings"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_graph_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "graph"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_attack_replay_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "attack_replay"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_missing_remediation_checklist_raises(self):
        data = {k: v for k, v in VALID_SCAN_RESULT.items() if k != "remediation_checklist"}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_nested_finding_invalid_line_type_raises(self):
        """Finding with non-int line inside ScanResultSchema should raise."""
        bad_finding = {**VALID_FINDING, "line": "twelve"}
        data = {**VALID_SCAN_RESULT, "findings": [bad_finding]}
        with pytest.raises(ValidationError):
            ScanResultSchema(**data)

    def test_scan_result_model_json_round_trip(self):
        """Serialise to JSON string and parse back."""
        result = ScanResultSchema(**VALID_SCAN_RESULT)
        json_str = result.model_dump_json()
        restored = ScanResultSchema.model_validate_json(json_str)
        assert restored == result
