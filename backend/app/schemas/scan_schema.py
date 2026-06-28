from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    id:            str = ""
    title:         str
    severity:      str
    category:      str
    file:          str
    line:          int
    why_it_matters: str
    suggested_fix: str
    description:   str = ""
    evidence:      str = ""


class CategoryScoresSchema(BaseModel):
    prompt_injection: int
    secret_exposure:  int
    tool_permission:  int
    human_approval:   int
    data_exposure:    int
    auditability:     int


class SummarySchema(BaseModel):
    critical: int
    high:     int
    medium:   int
    low:      int


class GraphNodeSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    id:    str
    label: str


class GraphEdgeSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str
    target: str
    risk:   str


class GraphSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    nodes: list[GraphNodeSchema]
    edges: list[GraphEdgeSchema]


class AttackSimulationSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    finding_id: str
    title: str
    attack_goal: str
    malicious_input: str
    weakness_exploited: str
    expected_behavior: str
    impact: str
    required_fix: str
    risk_level: str
    simulation_type: str = ""
    file: str = ""
    line: int | None = None
    evidence: str = ""
    location: str = ""
    guardrail: str = ""
    priority_score: int = 0
    preconditions: list[str] = Field(default_factory=list)
    attack_steps: list[str] = Field(default_factory=list)
    detection_signal: str = ""
    safe_test_note: str = ""


class PatchPreviewSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    finding_id: str
    title: str
    file: str
    patch_type: str
    patch_filename: str = "patch-preview.patch"
    copy_label: str = "Copy patch preview"
    download_label: str = "Download .patch"
    before: str
    after: str
    diff: str
    explanation: str
    confidence: str = "medium"
    manual_review_required: bool = True
    line: int | None = None
    language: str = "text"
    apply_strategy: str = "preview_only"
    estimated_effort: str = "medium"
    risk_reduction: str = ""
    affected_controls: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    review_notes: list[str] = Field(default_factory=list)


class DeploymentGateSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: str
    decision_badge: str = ""
    minimum_safety_score: int = 75
    safety_score: int = 0
    gate_score: int = 0
    blockers: list[str] = Field(default_factory=list)
    recommended_policy: dict[str, Any] = Field(default_factory=dict)
    github_actions_yaml: str = ""
    policy_json: str = ""
    summary: str = ""
    decision_reason: str = ""
    required_action: str = ""
    next_actions: list[str] = Field(default_factory=list)
    workflow_filename: str = "adapt-agent-safety-gate.yml"
    policy_filename: str = "adapt-policy.json"
    download_assets: list[dict[str, Any]] = Field(default_factory=list)
    ci_secret_requirements: list[dict[str, str]] = Field(default_factory=list)
    category_blocker_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ScanResultSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_name:          str
    scan_type:             str
    safety_score:          int
    status:                str
    summary:               SummarySchema
    category_scores:       CategoryScoresSchema
    findings:              list[FindingSchema]
    graph:                 GraphSchema
    attack_replay:         list[str]
    remediation_checklist: list[str]

    attack_simulations: list[AttackSimulationSchema] = Field(default_factory=list)
    patches: list[PatchPreviewSchema] = Field(default_factory=list)
    deployment_gate: DeploymentGateSchema | None = None
    score_delta: dict[str, Any] | None = None

    ai_summary: str = ""
    ai_report_summary: str = ""
    ai_remediation_plan: list[str] = Field(default_factory=list)
    ai_next_steps: list[str] = Field(default_factory=list)
    ai_enrichment_status: str = "not_requested"
    saved_report: bool = False
    report_id: str | None = None
