"""FastAPI Gateway Server for AI Data Leak Guardian.

Bridges the React frontend to the authoritative Python detection, risk,
redaction, and evaluation engines. Provides safe, isolated in-memory session
vaults and serves the compiled frontend in production for IBM LinuxONE.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import sys
import time
from typing import Any, AsyncGenerator, Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dataset_loader import load_synthetic_jsonl
from detector import Detector
from evaluation import Evaluator
from frontend import SYNTHETIC_PRESETS
from models import (
    DetectionFinding,
    EvaluationReport,
    RedactionResult,
    RestorationResult,
    RiskAssessment,
    Severity,
)
from redactor import Redactor, RedactionSession
from risk import assess_risk

# Safe audit logger
logger = logging.getLogger("guardian_api")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [API] %(message)s"))
    logger.addHandler(handler)


# -----------------------------------------------------------------------------
# Global Singletons & Session Vault Manager
# -----------------------------------------------------------------------------
class SessionManager:
    """Session vault manager with timestamps and bounded cleanup."""

    def __init__(self, max_sessions: int = 200, ttl_seconds: int = 7200) -> None:
        self._redactor = Redactor()
        self._timestamps: Dict[str, float] = {}
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds

    def _cleanup_expired(self) -> None:
        """Purge sessions exceeding TTL or enforce capacity limit."""
        now = time.time()
        expired = [sid for sid, ts in self._timestamps.items() if (now - ts) > self.ttl_seconds]
        for sid in expired:
            self._redactor.clear_session(sid)
            self._timestamps.pop(sid, None)

        if len(self._timestamps) > self.max_sessions:
            # Evict oldest sessions
            sorted_sessions = sorted(self._timestamps.items(), key=lambda item: item[1])
            excess = len(sorted_sessions) - self.max_sessions
            for sid, _ in sorted_sessions[:excess]:
                self._redactor.clear_session(sid)
                self._timestamps.pop(sid, None)

    def get_or_create(self, session_id: Optional[str] = None) -> RedactionSession:
        self._cleanup_expired()
        sid = session_id.strip() if session_id and session_id.strip() else f"sess_{uuid.uuid4().hex[:12]}"
        session = self._redactor.get_or_create_session(sid)
        self._timestamps[sid] = time.time()
        return session

    def get_existing(self, session_id: str) -> Optional[RedactionSession]:
        self._cleanup_expired()
        if session_id in self._redactor._sessions:
            self._timestamps[session_id] = time.time()
            return self._redactor._sessions[session_id]
        return None

    def purge_session(self, session_id: str) -> bool:
        cleared = self._redactor.clear_session(session_id)
        self._timestamps.pop(session_id, None)
        return cleared

    @property
    def active_session_count(self) -> int:
        return len(self._redactor._sessions)


# Application state
detector_instance: Optional[Detector] = None
session_manager = SessionManager()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager to load and warm expensive models once."""
    global detector_instance
    logger.info("Initializing unified hybrid detector...")
    detector_instance = Detector()
    logger.info(
        "Detector initialized. ML Available: %s (Mode: %s)",
        detector_instance.is_ml_available,
        "Hybrid spaCy NER" if detector_instance.is_ml_available else "Rules-Only Fallback",
    )
    yield
    logger.info("Shutting down API server and purging in-memory vaults...")
    # Safe cleanup on shutdown
    for sid in list(session_manager._redactor._sessions.keys()):
        session_manager.purge_session(sid)


app = FastAPI(
    title="AI Data Leak Guardian API",
    description="Secure Sensitive Data Detection, Risk Assessment, and Reversible Redaction Gateway",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS configuration for local Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class SystemStatusResponse(BaseModel):
    backend_status: str = "ready"
    rules_active: bool = True
    ml_available: bool
    ml_model_name: Optional[str] = None
    active_vault_sessions: int
    platform: str = sys.platform
    python_version: str = sys.version.split()[0]


class FindingSchema(BaseModel):
    entity_type: str
    start: int
    end: int
    span_length: int
    severity: str
    rule_id: str
    confidence: float
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskSummarySchema(BaseModel):
    risk_level: str
    reasons: List[str]
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class RedactionSummarySchema(BaseModel):
    session_id: str
    masked_text: str
    placeholders_count: int
    unique_placeholders: int
    findings_redacted: int


class AnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=150000, description="Input payload for local inspection")
    session_id: Optional[str] = Field(default=None, max_length=128)


class AnalyzeResponse(BaseModel):
    session_id: str
    findings: List[FindingSchema]
    risk: RiskSummarySchema
    redaction: RedactionSummarySchema


class RestoreRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    ai_response: str = Field(..., max_length=200000)


class RestoreResponse(BaseModel):
    session_id: str
    restored_text: str
    restored_placeholders: List[str]
    unrestored_placeholders: List[str]
    is_fully_restored: bool


class SessionResetRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)


class SessionResetResponse(BaseModel):
    session_id: str
    cleared: bool
    active_placeholder_count: int


class PresetItem(BaseModel):
    id: str
    title: str
    content: str


class PresetsResponse(BaseModel):
    presets: List[PresetItem]


class MetricItem(BaseModel):
    category: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float


class EvaluationMetricsResponse(BaseModel):
    available: bool
    status_message: str
    test_dataset: Optional[str] = None
    total_test_records: Optional[int] = None
    matching_policy: Optional[str] = None
    ml_alone: Optional[Dict[str, Any]] = None
    rules_alone: Optional[Dict[str, Any]] = None
    hybrid: Optional[Dict[str, Any]] = None
    manifest: Optional[Dict[str, Any]] = None


class LiveBenchmarkResponse(BaseModel):
    total_records: int
    matching_policy: str
    micro_precision: float
    micro_recall: float
    micro_f1: float
    macro_f1: float
    per_entity: Dict[str, MetricItem]


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/status", response_model=SystemStatusResponse)
async def get_system_status() -> SystemStatusResponse:
    """Return live backend readiness and detector status."""
    global detector_instance
    if detector_instance is None:
        detector_instance = Detector()

    is_ml = detector_instance.is_ml_available
    return SystemStatusResponse(
        backend_status="ready",
        rules_active=True,
        ml_available=is_ml,
        ml_model_name="spacy_blank_en_ner" if is_ml else None,
        active_vault_sessions=session_manager.active_session_count,
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_and_redact(request: AnalyzeRequest) -> AnalyzeResponse:
    """Inspect input for sensitive data, assess risk, and perform reversible redaction.

    SECURITY INVARIANT:
    Raw sensitive matches are NEVER returned in the findings metadata or logs.
    """
    global detector_instance
    if detector_instance is None:
        detector_instance = Detector()

    raw_text = request.text
    if not raw_text or not raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inspection payload cannot be empty or whitespace.",
        )

    try:
        # 1. Detection
        findings = detector_instance.detect(raw_text)

        # 2. Risk assessment
        risk_result = assess_risk(findings)

        # 3. Session isolation and redaction
        session = session_manager.get_or_create(request.session_id)
        redaction_result = session.redact(raw_text, findings)

        # 4. Format findings without exposing raw secret text
        safe_findings: List[FindingSchema] = []
        for f in findings:
            safe_findings.append(
                FindingSchema(
                    entity_type=f.entity_type.value,
                    start=f.start,
                    end=f.end,
                    span_length=f.span_length,
                    severity=f.severity.value,
                    rule_id=f.rule_id,
                    confidence=f.confidence,
                    description=f.description,
                    metadata=f.metadata,
                )
            )

        logger.info(
            "Analysis complete for session %s. Risk: %s, Findings: %d, Redacted: %d",
            session.session_id,
            risk_result.risk_level.value,
            len(safe_findings),
            redaction_result.placeholders_count,
        )

        return AnalyzeResponse(
            session_id=session.session_id,
            findings=safe_findings,
            risk=RiskSummarySchema(
                risk_level=risk_result.risk_level.value,
                reasons=risk_result.reasons,
                findings_count=risk_result.findings_count,
                critical_count=risk_result.critical_count,
                high_count=risk_result.high_count,
                medium_count=risk_result.medium_count,
                low_count=risk_result.low_count,
            ),
            redaction=RedactionSummarySchema(
                session_id=session.session_id,
                masked_text=redaction_result.masked_text,
                placeholders_count=redaction_result.placeholders_count,
                unique_placeholders=redaction_result.unique_placeholders,
                findings_redacted=redaction_result.findings_redacted,
            ),
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Analysis pipeline error: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inspection pipeline encountered an internal error ({type(exc).__name__}).",
        )


@app.post("/api/restore", response_model=RestoreResponse)
async def restore_placeholders(request: RestoreRequest) -> RestoreResponse:
    """Locally decode placeholders in simulated response text using session vault."""
    session = session_manager.get_existing(request.session_id)
    if session is None:
        # If session doesn't exist, we safely treat all placeholders as unrestored
        # rather than crashing, maintaining security isolation.
        return RestoreResponse(
            session_id=request.session_id,
            restored_text=request.ai_response,
            restored_placeholders=[],
            unrestored_placeholders=list(set(re.findall(r"\[[A-Z_]+_\d+\]", request.ai_response))),
            is_fully_restored=False,
        )

    try:
        restoration = session.restore_detailed(request.ai_response)
        logger.info(
            "Restoration executed for session %s. Restored: %d, Unrestored: %d",
            session.session_id,
            len(restoration.restored_placeholders),
            len(restoration.unrestored_placeholders),
        )
        return RestoreResponse(
            session_id=session.session_id,
            restored_text=restoration.restored_text,
            restored_placeholders=restoration.restored_placeholders,
            unrestored_placeholders=restoration.unrestored_placeholders,
            is_fully_restored=restoration.is_fully_restored,
        )
    except Exception as exc:
        logger.error("Restoration error: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Restoration operation failed safely.",
        )


@app.post("/api/session/reset", response_model=SessionResetResponse)
async def reset_session_vault(request: SessionResetRequest) -> SessionResetResponse:
    """Purge in-memory vault mappings for the designated session."""
    cleared = session_manager.purge_session(request.session_id)
    logger.info("Purged vault for session %s (Cleared: %s)", request.session_id, cleared)
    return SessionResetResponse(
        session_id=request.session_id,
        cleared=cleared,
        active_placeholder_count=0,
    )


@app.get("/api/presets", response_model=PresetsResponse)
async def get_synthetic_presets() -> PresetsResponse:
    """Return verified synthetic presets to prevent hardcoding duplicate text."""
    preset_items: List[PresetItem] = []
    idx = 1
    for title, content in SYNTHETIC_PRESETS.items():
        if not content.strip():
            continue
        preset_items.append(
            PresetItem(
                id=f"preset_{idx}",
                title=title,
                content=content,
            )
        )
        idx += 1
    return PresetsResponse(presets=preset_items)


@app.get("/api/evaluation/metrics", response_model=EvaluationMetricsResponse)
async def get_evaluation_metrics() -> EvaluationMetricsResponse:
    """Read verified evaluation artifacts and manifest metadata."""
    report_path = PROJECT_ROOT / "models" / "pii_ner" / "evaluation_report.json"
    manifest_path = PROJECT_ROOT / "models" / "pii_ner" / "manifest.json"

    if not report_path.is_file():
        return EvaluationMetricsResponse(
            available=False,
            status_message="Evaluation report artifact missing at models/pii_ner/evaluation_report.json",
        )

    try:
        with open(report_path, "r", encoding="utf-8") as rf:
            report_data = json.load(rf)

        manifest_data = None
        if manifest_path.is_file():
            with open(manifest_path, "r", encoding="utf-8") as mf:
                manifest_data = json.load(mf)

        return EvaluationMetricsResponse(
            available=True,
            status_message="Verified benchmark metrics loaded from trained model artifacts.",
            test_dataset=report_data.get("test_dataset"),
            total_test_records=report_data.get("total_test_records"),
            matching_policy=report_data.get("matching_policy"),
            ml_alone=report_data.get("ml_alone"),
            rules_alone=report_data.get("rules_alone"),
            hybrid=report_data.get("hybrid"),
            manifest=manifest_data,
        )
    except Exception as exc:
        return EvaluationMetricsResponse(
            available=False,
            status_message=f"Failed to read evaluation report ({type(exc).__name__}).",
        )


@app.post("/api/evaluation/benchmark", response_model=LiveBenchmarkResponse)
async def run_live_benchmark() -> LiveBenchmarkResponse:
    """Run live evaluation across verified test fixtures."""
    global detector_instance
    if detector_instance is None:
        detector_instance = Detector()

    pii_path = PROJECT_ROOT / "fixtures" / "synthetic_pii.jsonl"
    secrets_path = PROJECT_ROOT / "fixtures" / "synthetic_secrets.jsonl"

    if not pii_path.is_file() or not secrets_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Synthetic fixture files not found in fixtures/ directory.",
        )

    try:
        records = load_synthetic_jsonl(pii_path) + load_synthetic_jsonl(secrets_path)
        evaluator = Evaluator(detector=detector_instance)
        report: EvaluationReport = evaluator.evaluate_dataset(records)

        per_entity: Dict[str, MetricItem] = {}
        for cat, m in report.per_entity.items():
            per_entity[cat] = MetricItem(
                category=m.category,
                true_positives=m.true_positives,
                false_positives=m.false_positives,
                false_negatives=m.false_negatives,
                precision=m.precision,
                recall=m.recall,
                f1_score=m.f1_score,
            )

        return LiveBenchmarkResponse(
            total_records=report.total_records,
            matching_policy=report.matching_policy,
            micro_precision=report.overall_micro.precision,
            micro_recall=report.overall_micro.recall,
            micro_f1=report.overall_micro.f1_score,
            macro_f1=report.overall_macro_f1,
            per_entity=per_entity,
        )
    except Exception as exc:
        logger.error("Live benchmark execution error: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Live benchmark evaluation failed: {type(exc).__name__}",
        )


# -----------------------------------------------------------------------------
# Static Asset Serving for Production & LinuxONE Single-Port Execution
# -----------------------------------------------------------------------------
DIST_DIR = PROJECT_ROOT / "frontend" / "dist"

if DIST_DIR.is_dir():
    # Mount frontend static build directory
    app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_frontend(full_path: str):
        """Serve index.html for client-side routing on any non-API path."""
        target_file = DIST_DIR / full_path
        if full_path and target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(DIST_DIR / "index.html"))


# -----------------------------------------------------------------------------
# Main CLI Launcher
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser(description="AI Data Leak Guardian API Gateway")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable live auto-reload for dev")
    args = parser.parse_args()

    print("=" * 72)
    print("AI DATA LEAK GUARDIAN - FASTAPI GATEWAY")
    print(f"Server starting on http://{args.host}:{args.port}")
    if DIST_DIR.is_dir():
        print(f"Frontend static bundle mounted from {DIST_DIR}")
    else:
        print("Frontend dist not yet built. Running in API-only / dev-proxy mode.")
    print("=" * 72)

    uvicorn.run("server:app", host=args.host, port=args.port, reload=args.reload)
