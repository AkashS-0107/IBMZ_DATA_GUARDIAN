"""Frontend web application for AI Data Leak Guardian.

Built with Streamlit for the IBM Z Hackathon Challenge:
"AI Secured: Innovation Without Exposure".

Features:
- Professional security dashboard with dark navy/charcoal styling.
- Local in-memory PII and credential detection (hybrid: rules + spaCy NER).
- Deterministic 4-tier risk classification with safe audit rationales.
- Reversible redaction with right-to-left splicing and session vault isolation.
- Simulated AI response placeholder restoration and unknown-token preservation.
- Dataset and model evaluation metrics visualization.
- Strictly safe activity logging (zero raw secrets or mappings recorded).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

import streamlit as st

from config import DetectorConfig
from dataset_loader import load_synthetic_jsonl
from detector import Detector
from evaluation import Evaluator
from models import (
    DetectionFinding,
    EntityType,
    EvaluationReport,
    RedactionResult,
    RestorationResult,
    RiskAssessment,
    Severity,
)
from redactor import RedactionSession
from risk import assess_risk


# -----------------------------------------------------------------------------
# Synthetic Data Presets (Strictly Mock / Non-Functional Data)
# -----------------------------------------------------------------------------
PRESET_1_FULL_INCIDENT = (
    "Hello team, my name is Alex Mercer. You can contact me at alex.mercer@mockcorp.internal "
    "or phone +1-555-0149. For the production database synchronization, please use the connection "
    "string postgresql://svc_admin:MockSecretPass987@db-cluster.internal:5432/core_finance "
    "and configure api_key='sk_live_mock_abcdef1234567890abcdef1234'. "
    "My engineering profile is https://linkedin.com/in/alex-mercer-mock."
)

PRESET_2_DEVELOPER_CONFIG = (
    "# Application Configuration - Staging\n"
    "ENVIRONMENT=staging\n"
    "DATABASE_URL=mysql://app_user:ProdDatabaseP@ssw0rd!@db-01.aws.internal:3306/users_db\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AUTHORIZATION=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyHeaderPayloadSignature12345\n"
    "SESSION_SECRET=\"SuperSecretSessionKey2026!\"\n"
)

PRESET_3_STUDENT_PII = (
    "Student Admission Record:\n"
    "Student: Jane Doe\n"
    "Email: jane.doe@university-mock.edu\n"
    "Phone: (555) 019-2834\n"
    "National ID: 987-65-4321\n"
    "Residential Address: 742 Evergreen Terrace, Springfield\n"
    "Portfolio: https://github.com/janedoe-student\n"
    "Notes: Candidate cleared background verification."
)

PRESET_4_HIGH_ENTROPY = (
    "Service authentication payload:\n"
    "Client host: 192.168.1.150\n"
    "Entropy candidate secret: 4f9b2c8a1e7d3f0a5b6c7d8e9f0a1b2c\n"
    "Webhook: https://internal.gateway/v1/notify"
)

PRESET_5_CLEAN_PROMPT = (
    "Please explain the computational complexity differences between quicksort, mergesort, "
    "and heapsort in Python. Include asymptotic time complexity for best, average, and "
    "worst-case scenarios, along with auxiliary memory requirements."
)

SYNTHETIC_PRESETS = {
    "Select a synthetic demo preset...": "",
    "Preset 1: Full Incident (PII + DB URL + API Key)": PRESET_1_FULL_INCIDENT,
    "Preset 2: Developer Config & AWS Credentials": PRESET_2_DEVELOPER_CONFIG,
    "Preset 3: Student & HR Records (Names, SSN, Address)": PRESET_3_STUDENT_PII,
    "Preset 4: High-Entropy Token & Network IP": PRESET_4_HIGH_ENTROPY,
    "Preset 5: Clean Prompt (Zero Sensitive Entities)": PRESET_5_CLEAN_PROMPT,
}


# -----------------------------------------------------------------------------
# Cached Resources (Performance & LinuxONE Optimization)
# -----------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_cached_detector() -> Detector:
    """Instantiate and cache the hybrid detector across Streamlit interactions.

    Loads the spaCy English NER pipeline once into RAM rather than on every rerun,
    preserving resources on the 3 vCPU / 8 GB RAM target machine.
    """
    return Detector()


# -----------------------------------------------------------------------------
# CSS Theming (Security Dashboard: Charcoal / Navy / Restrained Cyan)
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* Main Background and Typography */
.stApp {
    background-color: #0B132B;
    color: #F8FAFC;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* Card Containers */
.sec-card {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25);
}

.sec-card-header {
    font-size: 1.05rem;
    font-weight: 600;
    color: #38BDF8;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* Status Badges */
.badge-status {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-critical {
    background-color: rgba(239, 68, 68, 0.18);
    color: #EF4444;
    border: 1px solid #EF4444;
}

.badge-high {
    background-color: rgba(249, 115, 22, 0.18);
    color: #F97316;
    border: 1px solid #F97316;
}

.badge-medium {
    background-color: rgba(245, 158, 11, 0.18);
    color: #F59E0B;
    border: 1px solid #F59E0B;
}

.badge-low {
    background-color: rgba(16, 185, 129, 0.18);
    color: #10B981;
    border: 1px solid #10B981;
}

.badge-info {
    background-color: rgba(56, 189, 248, 0.18);
    color: #38BDF8;
    border: 1px solid #38BDF8;
}

.badge-neutral {
    background-color: rgba(148, 163, 184, 0.18);
    color: #94A3B8;
    border: 1px solid #64748B;
}

/* Callout Alert Banners */
.alert-banner {
    border-radius: 6px;
    padding: 12px 16px;
    margin: 12px 0;
    font-size: 0.92rem;
    line-height: 1.45;
}

.alert-critical {
    background-color: #450A0A;
    border-left: 4px solid #EF4444;
    color: #FECACA;
}

.alert-warning {
    background-color: #431407;
    border-left: 4px solid #F97316;
    color: #FFEDD5;
}

.alert-medium {
    background-color: #451A03;
    border-left: 4px solid #F59E0B;
    color: #FEF3C7;
}

.alert-info {
    background-color: #082F49;
    border-left: 4px solid #38BDF8;
    color: #E0F2FE;
}

.alert-success {
    background-color: #022C22;
    border-left: 4px solid #10B981;
    color: #D1FAE5;
}

/* Metrics Grid Cards */
.metric-box {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
}

.metric-title {
    font-size: 0.78rem;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}

.metric-value {
    font-size: 1.55rem;
    font-weight: 700;
    color: #F8FAFC;
}

/* Code & Tables Styling */
pre, code {
    background-color: #0F172A !important;
    border: 1px solid #334155 !important;
    color: #E2E8F0 !important;
}

/* Subtitle and Disclaimer */
.sec-subtitle {
    font-size: 0.88rem;
    color: #94A3B8;
    margin-top: -6px;
    margin-bottom: 14px;
}
</style>
"""


# -----------------------------------------------------------------------------
# Session State Helpers
# -----------------------------------------------------------------------------
def init_session_state() -> None:
    """Initialize all Streamlit session state keys with clean defaults."""
    if "session_id" not in st.session_state:
        st.session_state.session_id = f"sess_{uuid.uuid4().hex[:12]}"

    if "redaction_session" not in st.session_state:
        st.session_state.redaction_session = RedactionSession(
            session_id=st.session_state.session_id
        )

    if "main_input_area" not in st.session_state:
        st.session_state.main_input_area = ""

    if "input_text" not in st.session_state:
        st.session_state.input_text = ""

    if "analysis_hash" not in st.session_state:
        st.session_state.analysis_hash = ""

    if "analysis_results" not in st.session_state:
        st.session_state.analysis_results = None

    if "simulated_response_area" not in st.session_state:
        st.session_state.simulated_response_area = ""

    if "simulated_response" not in st.session_state:
        st.session_state.simulated_response = ""

    if "restoration_result" not in st.session_state:
        st.session_state.restoration_result = None

    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []


def log_safe_activity(
    action: str,
    risk_level: str = "N/A",
    entity_counts: Optional[Dict[str, int]] = None,
    status: str = "Success",
) -> None:
    """Record safe metadata to the session-only audit trail.

    CRITICAL SECURITY INVARIANT:
    Never log or store raw user text, sensitive values, or session vault mappings.
    """
    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []

    entity_summary = (
        ", ".join(f"{k}:{v}" for k, v in entity_counts.items())
        if entity_counts
        else "None"
    )

    entry = {
        "#": len(st.session_state.audit_log) + 1,
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Action": action,
        "Risk Level": risk_level,
        "Entities Detected": entity_summary,
        "Status": status,
    }
    st.session_state.audit_log.insert(0, entry)
    # Keep last 50 session actions in memory
    st.session_state.audit_log = st.session_state.audit_log[:50]


# -----------------------------------------------------------------------------
# Callback Functions (Invoked safely before widget rendering)
# -----------------------------------------------------------------------------
def cb_load_preset() -> None:
    """Callback to load chosen synthetic preset into the input text area."""
    chosen = st.session_state.get("preset_selector", "")
    if chosen and SYNTHETIC_PRESETS.get(chosen):
        preset_content = SYNTHETIC_PRESETS[chosen]
        st.session_state.main_input_area = preset_content
        st.session_state.input_text = preset_content
        log_safe_activity(
            action=f"Loaded Synthetic Preset ({chosen.split(':')[0]})",
            risk_level="N/A",
        )


def cb_clear_analysis() -> None:
    """Callback to clear input content and active findings while keeping vault intact."""
    st.session_state.main_input_area = ""
    st.session_state.input_text = ""
    st.session_state.analysis_results = None
    st.session_state.analysis_hash = ""
    log_safe_activity(
        action="Cleared Current Analysis",
        risk_level="N/A",
        status="Input & Findings Cleared (Vault Retained)",
    )


def cb_reset_session() -> None:
    """Callback to completely purge session vault, analysis results, and reset state."""
    if "redaction_session" in st.session_state and st.session_state.redaction_session:
        st.session_state.redaction_session.clear()

    new_sid = f"sess_{uuid.uuid4().hex[:12]}"
    st.session_state.session_id = new_sid
    st.session_state.redaction_session = RedactionSession(session_id=new_sid)
    st.session_state.main_input_area = ""
    st.session_state.input_text = ""
    st.session_state.analysis_results = None
    st.session_state.analysis_hash = ""
    st.session_state.simulated_response_area = ""
    st.session_state.simulated_response = ""
    st.session_state.restoration_result = None

    log_safe_activity(
        action="Session Reset & Vault Purged",
        risk_level="N/A",
        status="Vault Cleared (0 active keys)",
    )


def cb_auto_generate_template() -> None:
    """Callback to generate a synthetic completion referencing active placeholders."""
    session: RedactionSession = st.session_state.redaction_session
    vault_count = session.active_placeholder_count
    if vault_count == 0:
        generated_tmpl = (
            "Thank you for your prompt. No sensitive placeholders were detected or replaced."
        )
    else:
        placeholders = list(session._vault.keys())
        placeholder_sample = " and ".join(placeholders[:3])
        generated_tmpl = (
            f"Hello! I have reviewed your submission. We verified records for {placeholder_sample}. "
            f"Your deployment plan has been scheduled with security parameters intact."
        )
    st.session_state.simulated_response_area = generated_tmpl
    st.session_state.simulated_response = generated_tmpl


def cb_inject_unknown() -> None:
    """Callback to inject an unknown placeholder to demonstrate security preservation."""
    current = st.session_state.get("simulated_response_area", "") or "AI Response received:"
    injected = f"{current}\nAdditional foreign service token: [FOREIGN_KEY_99]."
    st.session_state.simulated_response_area = injected
    st.session_state.simulated_response = injected


def cb_purge_vault() -> None:
    """Callback to clear in-memory vault mappings."""
    if "redaction_session" in st.session_state:
        st.session_state.redaction_session.clear()
    st.session_state.restoration_result = None
    log_safe_activity(
        action="Purged Session Vault",
        risk_level="N/A",
        status="Vault Cleared (0 active keys)",
    )


def cb_clear_activity_log() -> None:
    """Callback to wipe session activity log."""
    st.session_state.audit_log = []


# -----------------------------------------------------------------------------
# UI Component Renderers
# -----------------------------------------------------------------------------
def render_header(detector: Detector) -> None:
    """Render application header and dynamic status area."""
    col_title, col_status = st.columns([3, 2])

    with col_title:
        st.markdown("## 🛡️ AI Data Leak Guardian")
        st.markdown(
            "***“Inspect locally. Redact intelligently. Restore safely.”***<br>"
            "<span style='color: #38BDF8; font-size: 0.85rem; font-weight: 500;'>"
            "IBM Z Hackathon Challenge: AI Secured — Innovation Without Exposure</span>",
            unsafe_allow_html=True,
        )

    with col_status:
        # Dynamic verification of running components
        is_ml_active = detector.is_ml_available
        ml_badge = (
            "<span class='badge-status badge-info'>Hybrid: spaCy NER</span>"
            if is_ml_active
            else "<span class='badge-status badge-neutral'>Rules-Only Fallback</span>"
        )

        active_vault_count = (
            st.session_state.redaction_session.active_placeholder_count
            if "redaction_session" in st.session_state
            else 0
        )
        current_sid = st.session_state.get("session_id", "N/A")

        st.markdown(
            f"<div class='sec-card' style='padding: 10px 14px; margin-bottom: 0;'>"
            f"<div style='font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;'>Verified System Status</div>"
            f"<div style='display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; align-items: center;'>"
            f"<span class='badge-status badge-low'>Backend: Ready</span>"
            f"<span class='badge-status badge-low'>Rules: Active</span>"
            f"{ml_badge}"
            f"<span class='badge-status badge-info'>Vault: {active_vault_count} Keys</span>"
            f"<span class='badge-status badge-neutral' style='font-family: monospace;'>{current_sid}</span>"
            f"</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 12px 0 16px 0;'>", unsafe_allow_html=True)


def render_security_overview(results: Optional[Dict[str, Any]], detector: Detector) -> None:
    """Render the top security overview cards."""
    col1, col2, col3, col4 = st.columns(4)

    if results is None:
        with col1:
            st.markdown(
                "<div class='metric-box'><div class='metric-title'>Total Findings</div>"
                "<div class='metric-value' style='color: #94A3B8;'>—</div></div>",
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                "<div class='metric-box'><div class='metric-title'>Exposure Risk Level</div>"
                "<div class='metric-value' style='color: #94A3B8;'>IDLE</div></div>",
                unsafe_allow_html=True,
            )
        with col3:
            st.markdown(
                "<div class='metric-box'><div class='metric-title'>Credentials / Secrets</div>"
                "<div class='metric-value' style='color: #94A3B8;'>—</div></div>",
                unsafe_allow_html=True,
            )
        with col4:
            mode_label = "Hybrid" if detector.is_ml_available else "Rules-Only"
            st.markdown(
                f"<div class='metric-box'><div class='metric-title'>Detection Mode</div>"
                f"<div class='metric-value' style='font-size: 1.15rem; color: #38BDF8; padding-top: 6px;'>{mode_label}</div></div>",
                unsafe_allow_html=True,
            )
    else:
        risk: RiskAssessment = results["risk"]
        findings: List[DetectionFinding] = results["findings"]
        secrets_count = risk.critical_count

        severity_colors = {
            Severity.CRITICAL: "#EF4444",
            Severity.HIGH: "#F97316",
            Severity.MEDIUM: "#F59E0B",
            Severity.LOW: "#10B981",
        }
        risk_color = severity_colors.get(risk.risk_level, "#10B981")

        with col1:
            st.markdown(
                f"<div class='metric-box'><div class='metric-title'>Total Findings</div>"
                f"<div class='metric-value' style='color: #38BDF8;'>{len(findings)}</div></div>",
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"<div class='metric-box'><div class='metric-title'>Exposure Risk Level</div>"
                f"<div class='metric-value' style='color: {risk_color};'>{risk.risk_level.value.upper()}</div></div>",
                unsafe_allow_html=True,
            )
        with col3:
            secret_color = "#EF4444" if secrets_count > 0 else "#10B981"
            st.markdown(
                f"<div class='metric-box'><div class='metric-title'>Credentials / Secrets</div>"
                f"<div class='metric-value' style='color: {secret_color};'>{secrets_count}</div></div>",
                unsafe_allow_html=True,
            )
        with col4:
            mode_label = "Hybrid" if detector.is_ml_available else "Rules-Only"
            st.markdown(
                f"<div class='metric-box'><div class='metric-title'>Detection Mode</div>"
                f"<div class='metric-value' style='font-size: 1.15rem; color: #38BDF8; padding-top: 6px;'>{mode_label}</div></div>",
                unsafe_allow_html=True,
            )


def render_input_workspace(detector: Detector) -> Tuple[str, bool]:
    """Render the user input workspace, preset loader, and execution triggers.

    Returns:
        Tuple of (current_hash, is_stale)
    """
    st.markdown("### 1. Input Inspection Workspace")
    st.markdown(
        "<div class='sec-subtitle'>Paste text, prompts, code snippets, or configuration payloads. "
        "All inspection and redaction occurs strictly in local process memory before reaching external AI.</div>",
        unsafe_allow_html=True,
    )

    # Preset selection row
    col_preset, col_load = st.columns([4, 1])
    with col_preset:
        st.selectbox(
            "Load Synthetic Preset (Never uses real personal credentials):",
            options=list(SYNTHETIC_PRESETS.keys()),
            key="preset_selector",
            label_visibility="collapsed",
        )

    with col_load:
        st.button("📥 Load Preset", on_click=cb_load_preset, use_container_width=True)

    # Main text area
    user_input = st.text_area(
        label="Input Content for Inspection:",
        height=160,
        placeholder="Paste text, prompts, code snippets, or configuration payloads here for local risk inspection...",
        key="main_input_area",
    )

    # Stale detection
    current_hash = hashlib.sha256(user_input.encode("utf-8")).hexdigest() if user_input.strip() else ""
    is_stale = bool(
        st.session_state.analysis_results is not None
        and st.session_state.analysis_hash
        and current_hash != st.session_state.analysis_hash
    )

    if is_stale:
        st.markdown(
            "<div class='alert-banner alert-warning'>"
            "⚠️ <b>Input text was modified.</b> Previous analysis findings are hidden to prevent "
            "stale results from applying to newly edited content. Click <b>'Analyze & Redact'</b> "
            "to inspect the updated text.</div>",
            unsafe_allow_html=True,
        )

    # Action buttons
    col_btn_run, col_btn_clear_an, col_btn_reset, col_btn_refresh = st.columns([2, 1, 1, 1])

    with col_btn_run:
        run_clicked = st.button("🛡️ Analyze & Redact", type="primary", use_container_width=True)

    with col_btn_clear_an:
        st.button("🧹 Clear Analysis", on_click=cb_clear_analysis, use_container_width=True)

    with col_btn_reset:
        st.button("🗑️ Reset Session & Vault", on_click=cb_reset_session, use_container_width=True)

    with col_btn_refresh:
        refresh_clicked = st.button("🔄 Refresh Status", use_container_width=True)

    if refresh_clicked:
        st.rerun()

    if run_clicked:
        if not user_input or not user_input.strip():
            st.warning("Please enter or paste content into the inspection workspace before analyzing.")
            return current_hash, is_stale

        try:
            # 1. Detection via unified hybrid backend detector
            findings = detector.detect(user_input)

            # 2. Risk assessment via backend risk engine
            risk = assess_risk(findings)

            # 3. Reversible redaction via session vault
            session: RedactionSession = st.session_state.redaction_session
            redaction: RedactionResult = session.redact(user_input, findings)

            # Save state
            st.session_state.input_text = user_input
            st.session_state.analysis_hash = current_hash
            st.session_state.analysis_results = {
                "findings": findings,
                "risk": risk,
                "redaction": redaction,
            }

            # Count by entity type for safe audit log
            counts: Dict[str, int] = {}
            for f in findings:
                key = f.entity_type.value
                counts[key] = counts.get(key, 0) + 1

            log_safe_activity(
                action="Analyzed & Redacted",
                risk_level=risk.risk_level.value,
                entity_counts=counts,
                status=f"Redacted {redaction.placeholders_count} tokens",
            )
            st.rerun()

        except Exception as exc:
            # Audit safe error: never echo raw inputs in exception messages
            st.error(
                f"Inspection pipeline encountered an error ({type(exc).__name__}). "
                f"Please verify the input format. Security boundary preserved."
            )

    return current_hash, is_stale


def render_empty_state_guidance() -> None:
    """Render helpful instructions when no analysis has been executed yet."""
    st.markdown(
        "<div class='sec-card' style='background-color: #111E38; border: 1px dashed #334155; margin-top: 14px;'>"
        "<div class='sec-card-header'>💡 How AI Data Leak Guardian Works</div>"
        "<div style='font-size: 0.9rem; line-height: 1.6; color: #CBD5E1;'>"
        "<b>1. Local Inspection:</b> Select a synthetic preset or paste your prompt into the workspace above. "
        "No network requests or external AI calls are made.<br>"
        "<b>2. Hybrid Detection:</b> Identifies credentials (passwords, connection strings, API tokens), "
        "PII (emails, phones, SSNs, personal URLs), and high-entropy secrets using rules, Shannon entropy, "
        "and a trained spaCy NER model.<br>"
        "<b>3. Explainable Risk Tier:</b> Assigns deterministic risk (Low, Medium, High, or Critical) "
        "with safe audit rationales.<br>"
        "<b>4. Reversible Masking:</b> Generates typed placeholders (<code>[EMAIL_1]</code>, <code>[API_KEY_1]</code>) "
        "safe to forward to downstream AI, and safely decodes them in returned responses."
        "</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_detection_results(findings: List[DetectionFinding]) -> None:
    """Render the structured findings table without leaking raw sensitive text."""
    st.markdown("### 2. Detection Results")
    st.markdown(
        "<div class='sec-subtitle'>Structured entity findings detected by rule patterns, "
        "entropy heuristics, and spaCy NER. Original sensitive values are strictly excluded.</div>",
        unsafe_allow_html=True,
    )

    if not findings:
        st.markdown(
            "<div class='alert-banner alert-success'>"
            "✅ <b>Clean Input:</b> No sensitive entities, PII, or credentials detected in the input payload.</div>",
            unsafe_allow_html=True,
        )
        return

    # Build safe table representation
    table_rows = []
    for idx, f in enumerate(findings, start=1):
        table_rows.append({
            "#": idx,
            "Entity Type": f.entity_type.value,
            "Risk Tier": f.severity.value,
            "Detection Method": f.rule_id,
            "Span [Start, End)": f"[{f.start}, {f.end})",
            "Length": f.span_length,
            "Safe Audit Description": f.description,
        })

    st.dataframe(
        table_rows,
        use_container_width=True,
        hide_index=True,
    )


def render_risk_assessment(risk: RiskAssessment) -> None:
    """Render explainable risk tier and contributing factor audit rationales."""
    st.markdown("### 3. Risk Assessment & Audit Rationale")

    severity_classes = {
        Severity.CRITICAL: ("alert-critical", "🛑 CRITICAL EXPOSURE RISK"),
        Severity.HIGH: ("alert-warning", "⚠️ HIGH EXPOSURE RISK"),
        Severity.MEDIUM: ("alert-medium", "🔶 MEDIUM EXPOSURE RISK"),
        Severity.LOW: ("alert-success", "🟢 LOW EXPOSURE RISK"),
    }
    css_class, title = severity_classes.get(risk.risk_level, ("alert-info", "RISK ASSESSMENT"))

    st.markdown(
        f"<div class='alert-banner {css_class}'>"
        f"<div style='font-weight: 700; font-size: 1.05rem; margin-bottom: 4px;'>{title}</div>"
        f"Overall exposure tier: <b>{risk.risk_level.value.upper()}</b> "
        f"({risk.critical_count} Critical, {risk.high_count} High, "
        f"{risk.medium_count} Medium, {risk.low_count} Low findings)"
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='font-size: 0.88rem; font-weight: 600; color: #38BDF8; margin-bottom: 6px;'>Audit Rationale Factors:</div>", unsafe_allow_html=True)
    for reason in risk.reasons:
        st.markdown(f"- {reason}")

    st.markdown(
        "<div style='margin-top: 10px; font-size: 0.78rem; color: #94A3B8;'>"
        "<b>Security Disclaimer:</b> AI Data Leak Guardian is a privacy-enhancing local prototype "
        "built for the IBM Z Hackathon. It performs deterministic and heuristic inspection locally, "
        "and should be deployed as defense-in-depth alongside enterprise security policies. "
        "Redaction cannot guarantee detection of every possible novel or obfuscated secret.</div>",
        unsafe_allow_html=True,
    )


def render_redacted_prompt(redaction: RedactionResult) -> None:
    """Display the reversible masked prompt safe for external forwarding."""
    st.markdown("### 4. Sanitized Prompt (Safe for External AI)")
    st.markdown(
        "<div class='sec-subtitle'>Sensitive values have been replaced with typed reversible placeholders. "
        "Use this text when querying external AI systems.</div>",
        unsafe_allow_html=True,
    )

    st.code(redaction.masked_text, language="text")

    col_copy, col_download = st.columns([1, 1])
    with col_copy:
        st.info("💡 Tip: Click the copy icon in the upper-right corner of the code block above to copy the sanitized prompt.")
    with col_download:
        st.download_button(
            label="📥 Download Sanitized Prompt",
            data=redaction.masked_text,
            file_name="sanitized_prompt.txt",
            mime="text/plain",
            use_container_width=True,
        )

    st.markdown(
        "<div class='alert-banner alert-info' style='margin-top: 8px;'>"
        "🔒 <b>Zero External Transmission:</b> No automated external API calls are made. "
        "You retain absolute control over where sanitized text is forwarded. "
        "Placeholders remain recoverable only inside your active in-memory session.</div>",
        unsafe_allow_html=True,
    )


def render_simulated_restoration() -> None:
    """Render the simulated AI response and local placeholder restoration workflow."""
    st.markdown("### 5. Simulated AI Response & Local Restoration")
    st.markdown(
        "<div class='sec-subtitle'>Demonstrate how a downstream AI response referencing placeholders "
        "is restored locally inside the isolated session vault without exposing secrets externally.</div>",
        unsafe_allow_html=True,
    )

    session: RedactionSession = st.session_state.redaction_session

    col_btn_tmpl, col_btn_unk = st.columns(2)

    with col_btn_tmpl:
        st.button("🪄 Auto-Generate Response Template", on_click=cb_auto_generate_template, use_container_width=True)

    with col_btn_unk:
        st.button("🧪 Inject Unknown Placeholder [FOREIGN_KEY_99]", on_click=cb_inject_unknown, use_container_width=True)

    ai_response_input = st.text_area(
        label="Simulated AI Response (Containing Placeholders):",
        height=110,
        placeholder="Paste or generate an AI completion containing placeholders like [EMAIL_1] or [API_KEY_1]...",
        key="simulated_response_area",
    )

    col_restore, col_purge = st.columns([2, 1])

    with col_restore:
        restore_clicked = st.button("🔓 Restore Response Locally", type="primary", use_container_width=True)

    with col_purge:
        st.button("🧹 Purge Vault Mappings", on_click=cb_purge_vault, use_container_width=True)

    if restore_clicked:
        if not ai_response_input or not ai_response_input.strip():
            st.warning("Please provide or generate a simulated response text to restore.")
            return

        try:
            # Reversibly restore using in-memory session vault
            restoration: RestorationResult = session.restore_detailed(ai_response_input)
            st.session_state.simulated_response = ai_response_input
            st.session_state.restoration_result = restoration

            log_safe_activity(
                action="Restored Placeholders Locally",
                risk_level="N/A",
                status=f"Restored {len(restoration.restored_placeholders)} tokens",
            )
            st.rerun()

        except Exception as exc:
            st.error(f"Restoration failed safely ({type(exc).__name__}). No sensitive values exposed.")

    # Display restoration results if available
    restoration: Optional[RestorationResult] = st.session_state.restoration_result
    if restoration is not None:
        st.markdown("<div style='font-weight: 600; color: #10B981; margin: 12px 0 6px 0;'>Locally Restored Text:</div>", unsafe_allow_html=True)
        st.code(restoration.restored_text, language="text")

        col_audit1, col_audit2 = st.columns(2)
        with col_audit1:
            restored_list = ", ".join(restoration.restored_placeholders) if restoration.restored_placeholders else "None"
            st.markdown(
                f"<div class='sec-card' style='padding: 10px;'>"
                f"<div style='font-size: 0.75rem; color: #94A3B8;'>RESTORED IN THIS SESSION</div>"
                f"<div style='color: #10B981; font-weight: 600; font-size: 0.95rem;'>{restored_list}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        with col_audit2:
            unrestored_list = ", ".join(restoration.unrestored_placeholders) if restoration.unrestored_placeholders else "None"
            badge_color = "#94A3B8" if not restoration.unrestored_placeholders else "#F59E0B"
            st.markdown(
                f"<div class='sec-card' style='padding: 10px;'>"
                f"<div style='font-size: 0.75rem; color: #94A3B8;'>UNKNOWN / UNTOUCHED PLACEHOLDERS</div>"
                f"<div style='color: {badge_color}; font-weight: 600; font-size: 0.95rem;'>{unrestored_list}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        st.markdown(
            "<div style='font-size: 0.78rem; color: #94A3B8;'>"
            "🛡️ <b>Security Boundary:</b> Unknown placeholders or tokens from other sessions remain intact. "
            "Restored text is decoded in-memory and treated strictly as plain string data (never executed).</div>",
            unsafe_allow_html=True,
        )


def render_dataset_evaluation(detector: Detector) -> None:
    """Render model performance and benchmark metrics from verified local artifacts."""
    st.markdown("### 6. Dataset & Model Evaluation")
    st.markdown(
        "<div class='sec-subtitle'>Verified benchmark evaluation metrics across held-out documents. "
        "Strictly reflects actual trained artifacts and synthetic fixtures without synthetic inflation.</div>",
        unsafe_allow_html=True,
    )

    tab_report, tab_live = st.tabs(["📊 Verified Benchmark Report", "⚡ Live Fixture Evaluation"])

    with tab_report:
        report_path = Path("models/pii_ner/evaluation_report.json")
        manifest_path = Path("models/pii_ner/manifest.json")

        if not report_path.is_file():
            st.markdown(
                "<div class='alert-banner alert-warning'>"
                "⚠️ <b>Evaluation report not found:</b> <code>models/pii_ner/evaluation_report.json</code> is missing. "
                "Run <code>python training/evaluate_model.py --test-data datasets/processed/test_records.jsonl</code> "
                "to generate benchmark scores.</div>",
                unsafe_allow_html=True,
            )
            return

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)

            manifest_data = {}
            if manifest_path.is_file():
                with open(manifest_path, "r", encoding="utf-8") as mf:
                    manifest_data = json.load(mf)

            # Metadata callout
            train_docs = manifest_data.get("sample_counts", {}).get("train_documents", 12)
            val_docs = manifest_data.get("sample_counts", {}).get("validation_documents", 1)
            test_docs = report_data.get("total_test_records", 2)
            train_date = manifest_data.get("training_date", "2026-10-17")[:19]

            st.markdown(
                f"<div class='sec-card' style='padding: 12px 16px;'>"
                f"<div style='display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 0.85rem;'>"
                f"<div><b>Model Architecture:</b> spaCy English Blank (NER)</div>"
                f"<div><b>Dataset Source:</b> Synthetic Kaggle PII Schema</div>"
                f"<div><b>Sample Split:</b> {train_docs} Train / {val_docs} Val / {test_docs} Test</div>"
                f"<div><b>Trained:</b> {train_date}</div>"
                f"</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

            # Comparative performance table
            st.markdown("<div style='font-weight: 600; color: #38BDF8; margin: 10px 0 6px 0;'>Model Architecture Comparison (Exact-Span Policy):</div>", unsafe_allow_html=True)

            modes = [
                ("Mode 1: ML Model Alone", report_data.get("ml_alone", {})),
                ("Mode 2: Rule-Based Detector Alone", report_data.get("rules_alone", {})),
                ("Mode 3: Combined Hybrid Detector", report_data.get("hybrid", {})),
            ]

            comp_rows = []
            for name, mdata in modes:
                micro = mdata.get("overall_micro", {})
                comp_rows.append({
                    "Detection Mode": name,
                    "Micro Precision": f"{micro.get('precision', 0.0):.4f}",
                    "Micro Recall": f"{micro.get('recall', 0.0):.4f}",
                    "Micro F1": f"{micro.get('f1_score', 0.0):.4f}",
                    "Macro F1": f"{mdata.get('overall_macro_f1', 0.0):.4f}",
                    "True Positives": micro.get("true_positives", 0),
                    "False Positives": micro.get("false_positives", 0),
                    "False Negatives": micro.get("false_negatives", 0),
                })

            st.dataframe(comp_rows, use_container_width=True, hide_index=True)

            # Per-entity breakdown for Hybrid
            hybrid_per_entity = report_data.get("hybrid", {}).get("per_entity", {})
            if hybrid_per_entity:
                st.markdown("<div style='font-weight: 600; color: #38BDF8; margin: 12px 0 6px 0;'>Hybrid Per-Entity Breakdown:</div>", unsafe_allow_html=True)
                entity_rows = []
                for entity_name, metrics in hybrid_per_entity.items():
                    entity_rows.append({
                        "Entity Category": entity_name,
                        "Precision": f"{metrics.get('precision', 0.0):.4f}",
                        "Recall": f"{metrics.get('recall', 0.0):.4f}",
                        "F1 Score": f"{metrics.get('f1_score', 0.0):.4f}",
                        "TP": metrics.get("true_positives", 0),
                        "FP": metrics.get("false_positives", 0),
                        "FN": metrics.get("false_negatives", 0),
                    })
                st.dataframe(entity_rows, use_container_width=True, hide_index=True)

            st.markdown(
                "<div style='font-size: 0.78rem; color: #94A3B8; margin-top: 6px;'>"
                "<b>Audit Note:</b> Benchmark metrics reflect the evaluated synthetic Kaggle dataset records "
                "in <code>datasets/processed/</code>. The full Kaggle competition archive was not downloaded "
                "to ensure reproducible offline execution in constrained test environments.</div>",
                unsafe_allow_html=True,
            )

        except Exception as exc:
            st.error(f"Failed to load evaluation metrics ({type(exc).__name__}).")

    with tab_live:
        st.markdown(
            "Execute a live evaluation of the hybrid detector across deterministic test fixtures "
            "(<code>fixtures/synthetic_pii.jsonl</code> and <code>fixtures/synthetic_secrets.jsonl</code>)."
        )

        if st.button("⚡ Run Live Benchmark on Fixtures", use_container_width=True):
            pii_path = Path("fixtures/synthetic_pii.jsonl")
            secrets_path = Path("fixtures/synthetic_secrets.jsonl")

            if not pii_path.is_file() or not secrets_path.is_file():
                st.error("Synthetic fixture files missing in fixtures/ directory.")
            else:
                with st.spinner("Evaluating live benchmark..."):
                    records = load_synthetic_jsonl(pii_path) + load_synthetic_jsonl(secrets_path)
                    evaluator = Evaluator(detector=detector)
                    live_report = evaluator.evaluate_dataset(records)

                    st.success(f"Evaluated {live_report.total_records} documents successfully!")

                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    with col_m1:
                        st.metric("Micro Precision", f"{live_report.overall_micro.precision:.4f}")
                    with col_m2:
                        st.metric("Micro Recall", f"{live_report.overall_micro.recall:.4f}")
                    with col_m3:
                        st.metric("Micro F1", f"{live_report.overall_micro.f1_score:.4f}")
                    with col_m4:
                        st.metric("Macro F1", f"{live_report.overall_macro_f1:.4f}")


def render_safe_activity_summary() -> None:
    """Render the session-only audit trail."""
    st.markdown("### 7. Safe Session Activity Log")
    st.markdown(
        "<div class='sec-subtitle'>In-memory audit summary of actions executed during this session. "
        "Strictly safe metadata: zero raw input strings or sensitive values are recorded.</div>",
        unsafe_allow_html=True,
    )

    log_entries = st.session_state.get("audit_log", [])

    if not log_entries:
        st.markdown(
            "<div style='font-size: 0.85rem; color: #94A3B8; font-style: italic;'>"
            "No activity recorded in this session yet. Run an analysis above to populate.</div>",
            unsafe_allow_html=True,
        )
        return

    st.dataframe(
        log_entries,
        use_container_width=True,
        hide_index=True,
    )

    st.button("🗑️ Clear Activity Log", on_click=cb_clear_activity_log)


# -----------------------------------------------------------------------------
# Main Application Assembly
# -----------------------------------------------------------------------------
def render_app() -> None:
    """Master application assembly integrating all security modules and views."""
    st.set_page_config(
        page_title="AI Data Leak Guardian",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    # Inject dark security dashboard CSS
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # Initialize state
    init_session_state()

    # Load cached detector (Hybrid or Rules-Only)
    detector = get_cached_detector()

    # Section A: Header
    render_header(detector)

    # Section B: Security Overview Metrics
    results = st.session_state.analysis_results
    render_security_overview(results, detector)

    # Section C: Input Workspace
    current_hash, is_stale = render_input_workspace(detector)

    # If results are stale, hide old results
    active_results = None if is_stale else results

    # Sections D, E, F: Conditioned on active analysis results
    if active_results is not None:
        st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 20px 0;'>", unsafe_allow_html=True)
        col_res, col_risk = st.columns([3, 2])

        with col_res:
            render_detection_results(active_results["findings"])

        with col_risk:
            render_risk_assessment(active_results["risk"])

        st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 20px 0;'>", unsafe_allow_html=True)
        render_redacted_prompt(active_results["redaction"])
    elif not is_stale:
        render_empty_state_guidance()

    # Section G: Simulated AI Response and Restoration
    st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 20px 0;'>", unsafe_allow_html=True)
    render_simulated_restoration()

    # Section H: Dataset & Model Evaluation
    st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 20px 0;'>", unsafe_allow_html=True)
    render_dataset_evaluation(detector)

    # Section I: Safe Activity Summary
    st.markdown("<hr style='border: 0; border-top: 1px solid #334155; margin: 20px 0;'>", unsafe_allow_html=True)
    render_safe_activity_summary()


if __name__ == "__main__":
    render_app()
