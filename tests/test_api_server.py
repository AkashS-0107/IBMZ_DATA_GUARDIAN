"""Comprehensive integration tests for FastAPI server gateway.

Validates:
- /api/status reporting and model availability
- /api/analyze detection, risk tiering, and reversible redaction
- Sensitive values excluded from findings, metadata, and responses
- /api/restore recognized vs unknown placeholders
- /api/session/reset vault clearing and subsequent restoration blocking
- Session isolation between distinct sessions
- /api/presets list and content
- /api/evaluation/metrics artifact inspection
- /api/evaluation/benchmark live fixture execution
- Empty and invalid input rejection (HTTP 400)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from server import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Create test client with lifespan event context."""
    with TestClient(app) as test_client:
        yield test_client


def test_status_endpoint(client: TestClient):
    """Verify status endpoint returns system readiness and detector configuration."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["backend_status"] == "ready"
    assert data["rules_active"] is True
    assert isinstance(data["ml_available"], bool)
    assert data["active_vault_sessions"] >= 0
    assert "python_version" in data


def test_analyze_endpoint_end_to_end_and_security(client: TestClient):
    """Verify analyze endpoint detects entities, assesses risk, and redacts.
    Crucially asserts zero raw secrets are exposed in findings.
    """
    secret_key = "sk_live_mock_abcdef1234567890abcdef1234"
    secret_email = "victim.secret@confidential.org"
    payload_text = f"Contact support at {secret_email} using api_key='{secret_key}'."

    response = client.post(
        "/api/analyze",
        json={"text": payload_text, "session_id": "test_sess_001"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["session_id"] == "test_sess_001"

    # Risk level must be Critical due to API key
    assert data["risk"]["risk_level"] == "Critical"
    assert data["risk"]["critical_count"] >= 1

    # Findings checks
    findings = data["findings"]
    assert len(findings) >= 2
    types = {f["entity_type"] for f in findings}
    assert "EMAIL" in types
    assert "API_KEY" in types

    # SECURITY CHECK: Raw secret values must NEVER appear in any finding description or metadata
    for finding in findings:
        assert secret_key not in finding["description"]
        assert secret_email not in finding["description"]
        assert secret_key not in finding["rule_id"]
        assert secret_email not in finding["rule_id"]
        for meta_val in finding["metadata"].values():
            assert secret_key not in str(meta_val)
            assert secret_email not in str(meta_val)

    # Redaction checks
    redaction = data["redaction"]
    assert "[EMAIL_1]" in redaction["masked_text"]
    assert "[API_KEY_1]" in redaction["masked_text"]
    assert secret_email not in redaction["masked_text"]
    assert secret_key not in redaction["masked_text"]


def test_analyze_rejects_empty_input(client: TestClient):
    """Verify empty or whitespace payloads return HTTP 400."""
    res1 = client.post("/api/analyze", json={"text": ""})
    assert res1.status_code == 400

    res2 = client.post("/api/analyze", json={"text": "   \n\t  "})
    assert res2.status_code == 400


def test_restore_and_unknown_placeholders(client: TestClient):
    """Verify restoration decodes known placeholders while preserving unknown tokens."""
    session_id = "test_sess_restore_002"
    sample_text = "Please reach out to support.agent@mockcorp.com immediately."

    # 1. Analyze and populate session vault
    res_an = client.post(
        "/api/analyze",
        json={"text": sample_text, "session_id": session_id},
    )
    assert res_an.status_code == 200
    assert "[EMAIL_1]" in res_an.json()["redaction"]["masked_text"]

    # 2. Restore simulated response containing recognized [EMAIL_1] and unknown [FOREIGN_TOKEN_99]
    simulated_ai = "Hello! Acknowledged for [EMAIL_1]. Connected to foreign node [FOREIGN_TOKEN_99]."
    res_rest = client.post(
        "/api/restore",
        json={"session_id": session_id, "ai_response": simulated_ai},
    )
    assert res_rest.status_code == 200
    rest_data = res_rest.json()

    # Recognized email decoded
    assert "support.agent@mockcorp.com" in rest_data["restored_text"]
    assert "[EMAIL_1]" in rest_data["restored_placeholders"]

    # Unknown placeholder preserved untouched
    assert "[FOREIGN_TOKEN_99]" in rest_data["restored_text"]
    assert "[FOREIGN_TOKEN_99]" in rest_data["unrestored_placeholders"]
    assert rest_data["is_fully_restored"] is False


def test_session_reset_purges_vault(client: TestClient):
    """Verify resetting session wipes vault and blocks future restorations."""
    session_id = "test_sess_purge_003"
    client.post(
        "/api/analyze",
        json={"text": "password='UltraSecurePassword999'", "session_id": session_id},
    )

    # Purge vault
    res_reset = client.post("/api/session/reset", json={"session_id": session_id})
    assert res_reset.status_code == 200
    assert res_reset.json()["cleared"] is True

    # Restoration attempt now leaves placeholder un-restored
    res_restore = client.post(
        "/api/restore",
        json={"session_id": session_id, "ai_response": "Found password: [PASSWORD_1]"},
    )
    assert res_restore.status_code == 200
    assert "[PASSWORD_1]" in res_restore.json()["restored_text"]
    assert "[PASSWORD_1]" in res_restore.json()["unrestored_placeholders"]


def test_session_isolation(client: TestClient):
    """Verify Session A and Session B maintain strictly isolated vaults."""
    sess_a = "session_alpha"
    sess_b = "session_beta"

    client.post("/api/analyze", json={"text": "Email is alpha@company.com", "session_id": sess_a})
    client.post("/api/analyze", json={"text": "Email is beta@company.com", "session_id": sess_b})

    # Session A restores [EMAIL_1]
    res_a = client.post("/api/restore", json={"session_id": sess_a, "ai_response": "[EMAIL_1]"})
    assert res_a.json()["restored_text"] == "alpha@company.com"

    # Session B restores [EMAIL_1]
    res_b = client.post("/api/restore", json={"session_id": sess_b, "ai_response": "[EMAIL_1]"})
    assert res_b.json()["restored_text"] == "beta@company.com"


def test_presets_endpoint(client: TestClient):
    """Verify /api/presets returns 5 synthetic presets."""
    response = client.get("/api/presets")
    assert response.status_code == 200
    data = response.json()
    presets = data["presets"]
    assert len(presets) == 5
    titles = [p["title"] for p in presets]
    assert any("Preset 1: Full Incident" in t for t in titles)
    assert any("Preset 5: Clean Prompt" in t for t in titles)


def test_evaluation_metrics_endpoint(client: TestClient):
    """Verify /api/evaluation/metrics reads local report artifact."""
    response = client.get("/api/evaluation/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["available"] is True
    assert "hybrid" in data
    assert data["matching_policy"] == "exact-span"
    assert data["total_test_records"] == 2


def test_evaluation_live_benchmark_endpoint(client: TestClient):
    """Verify /api/evaluation/benchmark runs live benchmark on synthetic fixtures."""
    response = client.post("/api/evaluation/benchmark")
    assert response.status_code == 200
    data = response.json()
    assert data["total_records"] == 18
    assert data["micro_precision"] > 0.0
    assert data["micro_recall"] > 0.0
    assert data["micro_f1"] > 0.0


def test_serves_static_frontend_in_production(client: TestClient):
    """Verify FastAPI serves the built React frontend index.html for SPA routes."""
    response = client.get("/")
    assert response.status_code == 200
    assert "<!doctype html>" in response.text.lower()
    assert "AI Data Leak Guardian" in response.text
