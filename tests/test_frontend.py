"""Frontend integration tests for AI Data Leak Guardian.

Validates:
- Application startup and rendering with Streamlit AppTest.
- Real backend integration (detection, risk assessment, redaction, restoration).
- Findings rendered without exposing raw sensitive values.
- Risk level and redacted output accuracy.
- Session isolation and vault purging.
- Safe handling of unknown placeholders.
- Model-unavailable fallback mode.
- Empty/whitespace input safety.
- Stale findings suppression.
- Audit trail safety (zero raw secrets logged).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import pytest
from streamlit.testing.v1 import AppTest

from config import DetectorConfig
from detector import Detector
from models import EntityType, Severity
from redactor import RedactionSession
from risk import assess_risk


FRONTEND_PATH = str(Path(__file__).resolve().parent.parent / "frontend.py")


def create_app_test() -> AppTest:
    return AppTest.from_file(FRONTEND_PATH, default_timeout=10)


def test_frontend_starts_successfully():
    """Verify application starts without errors and renders verified header status."""
    at = create_app_test().run()
    assert len(at.exception) == 0

    # Verify title and subtitle in markdown
    content = " ".join(m.value for m in at.markdown)
    assert "AI Data Leak Guardian" in content
    assert "Inspect locally. Redact intelligently. Restore safely." in content
    assert "Verified System Status" in content
    assert "Backend: Ready" in content
    assert "Rules: Active" in content


def test_preset_loading_updates_input():
    """Verify selecting and loading a synthetic preset updates the inspection workspace."""
    at = create_app_test().run()

    # Select Preset 1 (Full Incident)
    at.selectbox(key="preset_selector").select_index(1).run()

    # Click Load Preset
    load_btn = [b for b in at.button if "Load" in b.label][0]
    load_btn.click().run()

    assert len(at.exception) == 0
    loaded_val = at.session_state["main_input_area"]
    assert "Alex Mercer" in loaded_val
    assert "alex.mercer@mockcorp.internal" in loaded_val
    assert "sk_live_mock_" in loaded_val


def test_analyze_and_redact_end_to_end():
    """Verify Analyze & Redact calls the actual backend and populates findings and redaction."""
    at = create_app_test().run()

    sample_text = (
        "Contact me at test.user@company.org or phone +1-555-0199. "
        "The api_key='sk_live_mock_abcdef1234567890abcdef1234' is active."
    )
    at.session_state["main_input_area"] = sample_text
    at.run()

    # Click Analyze & Redact
    run_btn = [b for b in at.button if "Analyze & Redact" in b.label][0]
    run_btn.click().run()

    assert len(at.exception) == 0
    results = at.session_state.get("analysis_results")
    assert results is not None

    findings = results["findings"]
    assert len(findings) >= 3

    # Verify risk assessment is CRITICAL due to API key
    risk = results["risk"]
    assert risk.risk_level == Severity.CRITICAL
    assert risk.critical_count >= 1

    # Verify redaction result contains typed placeholders
    redaction = results["redaction"]
    assert "[EMAIL_1]" in redaction.masked_text
    assert "[PHONE_1]" in redaction.masked_text
    assert "[API_KEY_1]" in redaction.masked_text
    # Verify raw values are replaced
    assert "test.user@company.org" not in redaction.masked_text
    assert "sk_live_mock_abcdef1234567890abcdef1234" not in redaction.masked_text


def test_findings_rendered_without_exposing_raw_values():
    """Verify findings table excludes raw sensitive text."""
    at = create_app_test().run()

    sensitive_secret = "SuperSecretPassword123"
    sensitive_email = "victim.secret@confidential.org"
    sample_text = f"User email={sensitive_email} and password='{sensitive_secret}'."

    at.session_state["main_input_area"] = sample_text
    at.run()

    run_btn = [b for b in at.button if "Analyze & Redact" in b.label][0]
    run_btn.click().run()

    results = at.session_state.get("analysis_results")
    assert results is not None

    findings = results["findings"]
    for f in findings:
        # None of the public safe descriptions should contain the raw secret
        assert sensitive_secret not in f.description
        assert sensitive_email not in f.description
        assert sensitive_secret not in f.rule_id
        assert sensitive_email not in f.rule_id

    # Check safe session activity log
    audit_log = at.session_state.get("audit_log", [])
    for entry in audit_log:
        for val in entry.values():
            assert sensitive_secret not in str(val)
            assert sensitive_email not in str(val)


def test_risk_level_matches_backend():
    """Verify frontend overview cards accurately derive risk levels from the risk engine."""
    detector = Detector()

    # Case 1: Critical (Credential present)
    text_crit = "Database url postgresql://admin:SecretPass123@db:5432/main."
    findings_crit = detector.detect(text_crit)
    risk_crit = assess_risk(findings_crit)
    assert risk_crit.risk_level == Severity.CRITICAL

    at = create_app_test().run()
    at.session_state["main_input_area"] = text_crit
    at.run()
    [b for b in at.button if "Analyze & Redact" in b.label][0].click().run()
    assert at.session_state["analysis_results"]["risk"].risk_level == Severity.CRITICAL

    # Case 2: Clean text (Low risk)
    text_clean = "Explain time complexity of binary search."
    findings_clean = detector.detect(text_clean)
    risk_clean = assess_risk(findings_clean)
    assert risk_clean.risk_level == Severity.LOW

    at2 = create_app_test().run()
    at2.session_state["main_input_area"] = text_clean
    at2.run()
    [b for b in at2.button if "Analyze & Redact" in b.label][0].click().run()
    assert at2.session_state["analysis_results"]["risk"].risk_level == Severity.LOW


def test_simulated_restoration_and_unknown_placeholders():
    """Verify local placeholder restoration and unknown token preservation."""
    at = create_app_test().run()

    # 1. Analyze prompt with an email
    at.session_state["main_input_area"] = "Send update to dev.support@company.com please."
    at.run()
    [b for b in at.button if "Analyze & Redact" in b.label][0].click().run()

    # 2. Set simulated response containing recognized [EMAIL_1] and unknown [FOREIGN_TOKEN_99]
    simulated = "Response: Acknowledged for [EMAIL_1]. Unknown service: [FOREIGN_TOKEN_99]."
    at.session_state["simulated_response_area"] = simulated
    at.run()

    # 3. Click Restore Response Locally
    restore_btn = [b for b in at.button if "Restore Response Locally" in b.label][0]
    restore_btn.click().run()

    restoration = at.session_state.get("restoration_result")
    assert restoration is not None
    # [EMAIL_1] is restored to dev.support@company.com
    assert "dev.support@company.com" in restoration.restored_text
    assert "[EMAIL_1]" in restoration.restored_placeholders
    # [FOREIGN_TOKEN_99] is preserved untouched
    assert "[FOREIGN_TOKEN_99]" in restoration.restored_text
    assert "[FOREIGN_TOKEN_99]" in restoration.unrestored_placeholders
    assert restoration.is_fully_restored is False


def test_session_clearing_purges_mappings():
    """Verify resetting session or purging vault removes mappings and blocks restoration."""
    at = create_app_test().run()

    # 1. Analyze input
    at.session_state["main_input_area"] = "Admin key sk_live_mock_abcdef1234567890abcdef1234."
    at.run()
    [b for b in at.button if "Analyze & Redact" in b.label][0].click().run()

    session: RedactionSession = at.session_state["redaction_session"]
    assert session.active_placeholder_count >= 1

    # 2. Click Purge Vault Mappings
    purge_btn = [b for b in at.button if "Purge Vault Mappings" in b.label][0]
    purge_btn.click().run()

    assert session.active_placeholder_count == 0

    # 3. Attempting restoration now cannot recover values
    at.session_state["simulated_response_area"] = "Key is [API_KEY_1]."
    at.run()
    [b for b in at.button if "Restore Response Locally" in b.label][0].click().run()

    restoration = at.session_state.get("restoration_result")
    assert restoration is not None
    # [API_KEY_1] remains un-restored because vault was purged
    assert "[API_KEY_1]" in restoration.restored_text
    assert "[API_KEY_1]" in restoration.unrestored_placeholders


def test_clear_current_analysis():
    """Verify Clear Current Analysis clears input and findings while keeping vault intact."""
    at = create_app_test().run()

    at.session_state["main_input_area"] = "User email jane.doe@example.org."
    at.run()
    [b for b in at.button if "Analyze & Redact" in b.label][0].click().run()
    assert at.session_state.get("analysis_results") is not None

    # Click Clear Analysis
    clear_btn = [b for b in at.button if "Clear Analysis" in b.label][0]
    clear_btn.click().run()

    assert at.session_state.get("analysis_results") is None
    assert at.session_state.get("main_input_area") == ""


def test_stale_findings_suppression():
    """Verify that editing input after analysis marks findings stale and withholds old findings."""
    at = create_app_test().run()

    # 1. Analyze initial input
    at.session_state["main_input_area"] = "Original text with john.doe@example.com."
    at.run()
    [b for b in at.button if "Analyze & Redact" in b.label][0].click().run()
    assert at.session_state.get("analysis_results") is not None

    # 2. Modify input in text area without re-running analysis
    at.session_state["main_input_area"] = "Edited input with different content."
    at.run()

    # The stale warning banner should appear
    rendered = " ".join(m.value for m in at.markdown)
    assert "Input text was modified" in rendered
    assert "Previous analysis findings are hidden" in rendered


def test_empty_and_whitespace_input_handled_safely():
    """Verify empty or whitespace-only inputs trigger a warning and do not crash."""
    at = create_app_test().run()

    at.session_state["main_input_area"] = "   "
    at.run()

    run_btn = [b for b in at.button if "Analyze & Redact" in b.label][0]
    run_btn.click().run()

    assert len(at.exception) == 0
    assert at.session_state.get("analysis_results") is None
    # Warning message appears
    warnings = [w.value for w in at.warning]
    assert any("Please enter or paste content" in w for w in warnings)


def test_model_unavailable_fallback():
    """Verify application functions gracefully in rules-only fallback if ML model is missing."""
    config = DetectorConfig()
    config.ML_ENABLED = False
    detector = Detector(config=config, ml_detector=None)
    assert detector.is_ml_available is False

    # Detection continues to work with rules and entropy
    findings = detector.detect("Send email to test@company.com with password='MySecretPassword123'.")
    assert len(findings) >= 2
    types = {f.entity_type for f in findings}
    assert EntityType.EMAIL in types
    assert EntityType.PASSWORD in types


def test_live_benchmark_tab():
    """Verify Live Fixture Benchmark runs on fixtures without errors."""
    at = create_app_test().run()

    live_btn = [b for b in at.button if "Run Live Benchmark" in b.label]
    if live_btn:
        live_btn[0].click().run()
        assert len(at.exception) == 0
        successes = [s.value for s in at.success]
        assert any("Evaluated 18 documents successfully" in s for s in successes)
