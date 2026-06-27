import os
import tempfile
import uuid
from datetime import datetime
from dotenv import load_dotenv

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Load env variables before Firebase/Gemini modules are imported.
load_dotenv()

from app.github.github_url_validator import parse_github_repo_url
from app.github.repo_downloader import download_public_repo_zip
from app.ai.ai_enrichment import enrich_scan_result_with_ai
from app.graph import build_demo_graph
from app.risk.scoring import compute_status
from app.schemas.scan_schema import ScanResultSchema
from app.services.scan_pipeline import attach_v2_report_artifacts, build_scan_result
from app.deployment_gate.gate_policy import build_deployment_gate
from app.utils.zip_utils import validate_zip_meta, extract_zip, cleanup_temp_dir
from app.routes import auth
from app.utils.firebase_utils import get_db

# Security Assistant Import
from app.security_assistant.assistant_router import router as assistant_router

app = FastAPI(title="A-DAP-T Backend")

# Keep this permissive for now because frontend deployment URLs can change during V2.
# We can tighten it once the final Vercel URL is stable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Auth Routes
app.include_router(auth.router)

# Include Security Assistant Routes (Backend Only Integration)
app.include_router(assistant_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "A-DAP-T backend"
    }


def _serialize_graph(graph: dict) -> dict:
    if not graph or not isinstance(graph, dict):
        return graph

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    def _to_dict(obj):
        try:
            if hasattr(obj, "dict"):
                return obj.dict()
            if isinstance(obj, dict):
                return obj
            return {k: getattr(obj, k) for k in ("id", "label", "source", "target", "risk") if hasattr(obj, k)}
        except Exception:
            return obj

    return {"nodes": [_to_dict(n) for n in nodes], "edges": [_to_dict(e) for e in edges]}


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


async def _save_scan_to_db(result: dict, user_id: str | None = None) -> str | None:
    """Save a completed scan report for an authenticated user."""
    if not user_id:
        return None

    db = get_db()
    if not db:
        raise HTTPException(status_code=500, detail="Database is not configured")

    scan_id = str(uuid.uuid4())
    saved_at = _utc_now_iso()

    result_to_save = result.copy()
    result_to_save["id"] = scan_id
    result_to_save["user_id"] = user_id
    result_to_save["created_at"] = saved_at
    result_to_save["timestamp"] = saved_at  # kept for old /history sorting compatibility

    db.collection("scans").document(scan_id).set(result_to_save)
    return scan_id


def _with_save_metadata(result: dict, report_id: str | None) -> dict:
    result = result.copy()
    result["saved_report"] = report_id is not None
    result["report_id"] = report_id
    return result


async def _save_if_requested(result: dict, user: dict | None, save_report: bool) -> dict:
    if not save_report:
        return _with_save_metadata(result, None)

    if not user:
        raise HTTPException(status_code=401, detail="Authentication required to save reports")

    report_id = await _save_scan_to_db(result, user.get("uid"))
    return _with_save_metadata(result, report_id)


def _require_authenticated_user(user: dict | None) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user



@app.get("/scan/demo/vulnerable", response_model=ScanResultSchema)
async def scan_vulnerable_demo(
    save_report: bool = Query(False),
    user=Depends(auth.get_current_user),
):
    user = _require_authenticated_user(user)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vulnerable_dir = os.path.abspath(os.path.join(base_dir, "..", "sample_agents", "vulnerable-support-agent"))

    result = build_scan_result(
        vulnerable_dir,
        project_name="vulnerable-support-agent",
        scan_type="demo_vulnerable",
        enrich=False,
    )

    result["graph"] = _serialize_graph(build_demo_graph("demo_vulnerable"))
    result["attack_replay"] = [
        "Malicious prompt received",
        "Agent accepts fake admin role",
        "Agent reads internal policy",
        "Agent accesses customer record",
        "Agent calls issue_refund()",
        "No approval gate found",
        "Critical risk flagged",
    ]
    result["remediation_checklist"] = [
        "Move secrets to environment variables",
        "Add approval gate before refund actions",
        "Add audit logging for tool calls",
        "Mask sensitive customer data",
        "Keep system prompts server-side",
    ]

    # Demo scores are fixed before AI enrichment so Gemini summaries match the displayed report.
    result["safety_score"] = 32
    result["status"] = compute_status(32)
    result = attach_v2_report_artifacts(result)
    result = enrich_scan_result_with_ai(result)
    result = await _save_if_requested(result, user, save_report)

    return JSONResponse(result)


@app.get("/scan/demo/secured", response_model=ScanResultSchema)
async def scan_secured_demo(
    save_report: bool = Query(False),
    user=Depends(auth.get_current_user),
):
    user = _require_authenticated_user(user)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    secured_dir = os.path.abspath(os.path.join(base_dir, "..", "sample_agents", "secured-support-agent"))

    result = build_scan_result(
        secured_dir,
        project_name="secured-support-agent",
        scan_type="demo_secured",
        enrich=False,
    )

    result["graph"] = _serialize_graph(build_demo_graph("demo_secured"))
    result["attack_replay"] = [
        "Malicious prompt received",
        "Agent identifies risky refund request",
        "Sensitive customer data is masked",
        "Refund action is routed to human approval",
        "Tool call is logged",
        "Risk reduced",
    ]
    result["remediation_checklist"] = [
        "Continue adversarial testing",
        "Add more tool-level unit tests",
        "Monitor failed attack attempts",
        "Review approval logs periodically",
    ]

    # Demo scores are fixed before AI enrichment so Gemini summaries match the displayed report.
    result["safety_score"] = 94
    result["status"] = compute_status(94)
    result = attach_v2_report_artifacts(result)
    result = enrich_scan_result_with_ai(result)
    result = await _save_if_requested(result, user, save_report)

    return JSONResponse(result)


class DeploymentGateEvaluateRequest(BaseModel):
    scan_result: dict
    policy: dict | None = None


@app.post("/deployment-gate/evaluate")
async def evaluate_deployment_gate(
    payload: DeploymentGateEvaluateRequest,
    user=Depends(auth.get_current_user),
):
    _require_authenticated_user(user)
    return build_deployment_gate(payload.scan_result, payload.policy)


class GitHubScanRequest(BaseModel):
    repo_url: str
    branch: str | None = None
    save_report: bool = False


def _scan_zip_path(zip_path: str, project_name: str, scan_type: str, extra_metadata: dict | None = None) -> dict:
    validate_zip_meta(zip_path)

    target_dir = tempfile.mkdtemp()
    try:
        extract_zip(zip_path, target_dir)
        return build_scan_result(
            target_dir,
            project_name=project_name,
            scan_type=scan_type,
            extra_metadata=extra_metadata,
        )
    finally:
        cleanup_temp_dir(target_dir)


@app.post("/scan/upload", response_model=ScanResultSchema)
async def scan_upload(
    file: UploadFile = File(...),
    save_report: bool = Query(False),
    user=Depends(auth.get_current_user),
):
    user = _require_authenticated_user(user)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
        tmp_zip.write(await file.read())
        tmp_zip_path = tmp_zip.name

    try:
        result = _scan_zip_path(
            tmp_zip_path,
            project_name=file.filename or "uploaded_project",
            scan_type="upload",
        )
        result = await _save_if_requested(result, user, save_report)
        return JSONResponse(result)
    finally:
        if os.path.exists(tmp_zip_path):
            try:
                os.unlink(tmp_zip_path)
            except OSError:
                pass


@app.post("/scan/github", response_model=ScanResultSchema)
async def scan_github_repo(payload: GitHubScanRequest, user=Depends(auth.get_current_user)):
    user = _require_authenticated_user(user)
    repo = parse_github_repo_url(payload.repo_url, payload.branch)
    tmp_zip_path = download_public_repo_zip(repo)

    try:
        result = _scan_zip_path(
            tmp_zip_path,
            project_name=repo.display_name,
            scan_type="github_repo",
            extra_metadata={
                "repo_url": payload.repo_url,
                "repo_owner": repo.owner,
                "repo_name": repo.repo,
                "repo_branch": repo.branch or "main/master",
            },
        )
        result = await _save_if_requested(result, user, payload.save_report)
        return JSONResponse(result)
    finally:
        if os.path.exists(tmp_zip_path):
            try:
                os.unlink(tmp_zip_path)
            except OSError:
                pass


def _scan_summary(scan: dict) -> dict:
    return {
        "id": scan.get("id"),
        "project_name": scan.get("project_name"),
        "scan_type": scan.get("scan_type"),
        "repo_url": scan.get("repo_url"),
        "upload_name": scan.get("upload_name"),
        "safety_score": scan.get("safety_score"),
        "status": scan.get("status"),
        "summary": scan.get("summary"),
        "created_at": scan.get("created_at") or scan.get("timestamp"),
    }


async def _get_user_scan(user_id: str, scan_id: str) -> dict | None:
    db = get_db()
    if not db:
        raise HTTPException(status_code=500, detail="Database is not configured")

    doc = db.collection("scans").document(scan_id).get()
    if not doc.exists:
        return None

    scan = doc.to_dict()
    if scan.get("user_id") != user_id:
        return None
    return scan


@app.get("/history")
@app.get("/reports")
async def list_reports(user=Depends(auth.get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    db = get_db()
    if not db:
        raise HTTPException(status_code=500, detail="Database is not initialized")

    try:
        docs = db.collection("scans").where("user_id", "==", user["uid"]).order_by("timestamp", direction="DESCENDING").stream()
        scans = [doc.to_dict() for doc in docs]
    except Exception:
        # Firestore can require a composite index for ordered filtered queries.
        docs = db.collection("scans").where("user_id", "==", user["uid"]).stream()
        scans = [doc.to_dict() for doc in docs]
        scans.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    return [_scan_summary(scan) for scan in scans]


@app.get("/reports/{report_id}")
async def get_report(report_id: str, user=Depends(auth.get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    scan = await _get_user_scan(user["uid"], report_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")

    return scan


@app.delete("/reports/{report_id}")
async def delete_report(report_id: str, user=Depends(auth.get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    scan = await _get_user_scan(user["uid"], report_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")

    db = get_db()
    db.collection("scans").document(report_id).delete()
    return {"deleted": True, "report_id": report_id}
