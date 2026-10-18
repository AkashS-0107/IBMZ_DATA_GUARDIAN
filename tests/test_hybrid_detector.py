"""Automated unit and integration tests for ML PII Detector and Hybrid Detection Engine.

Tests:
1. Missing model directory and rules-only fallback.
2. Label taxonomy mapping and character offset bounds.
3. Precedence of critical credentials (passwords, private keys, API keys) over ML findings.
4. Deterministic conflict resolution for overlapping equal-severity findings.
5. Deduplication of identical findings between rules and ML.
6. Preservation of non-overlapping union of findings.
7. Safe exception handling: ML inference errors never disable rule-based security checks.
"""

from pathlib import Path
import pytest

from config import DetectorConfig
from detector import Detector, resolve_overlaps
from models import DetectionFinding, EntityType, Severity
from training.predict import MLPIIDetector


class TestMLPIIDetectorUnit:
    """Unit tests for MLPIIDetector class."""

    def test_missing_model_directory_fallback(self, tmp_path: Path):
        non_existent_dir = tmp_path / "non_existent_model_dir"
        detector = MLPIIDetector(model_path=non_existent_dir)
        assert detector.is_available() is False
        assert detector.detect("Hello world") == []

    def test_disabled_mode_returns_empty(self):
        detector = MLPIIDetector(model_path="models/pii_ner", enabled=False)
        assert detector.is_available() is False
        assert detector.detect("Student Bob Smith") == []

    def test_empty_and_whitespace_input_returns_empty(self):
        detector = MLPIIDetector(model_path="models/pii_ner")
        assert detector.detect("") == []
        assert detector.detect("   \n\t   ") == []

    def test_label_taxonomy_normalization(self):
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["NAME"] == EntityType.NAME
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["NAME_STUDENT"] == EntityType.NAME
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["EMAIL"] == EntityType.EMAIL
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["PHONE_NUM"] == EntityType.PHONE
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["URL_PERSONAL"] == EntityType.PERSONAL_URL
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["ID_NUM"] == EntityType.ID_NUMBER
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["STREET_ADDRESS"] == EntityType.STREET_ADDRESS
        assert MLPIIDetector.LABEL_TAXONOMY_MAP["USERNAME"] == EntityType.USERNAME

    def test_inference_exception_safety(self, monkeypatch):
        detector = MLPIIDetector(model_path="models/pii_ner")
        if detector.is_available():
            # Force an internal error in spaCy nlp call
            def mock_nlp_error(text):
                raise RuntimeError("Simulated internal spaCy error")

            monkeypatch.setattr(detector, "_nlp", mock_nlp_error)
            findings = detector.detect("Test input text")
            # Must safely return [] without propagating unhandled error
            assert findings == []


class TestHybridConflictResolution:
    """Tests for conflict resolution between rule-based detections and ML detections."""

    def test_credential_precedence_over_overlapping_ml_finding(self):
        # Suppose ML falsely detects a NAME spanning across a password assignment
        ml_finding = DetectionFinding(
            entity_type=EntityType.NAME,
            start=10,
            end=30,
            severity=Severity.MEDIUM,
            rule_id="ml:spacy_ner:name",
            confidence=0.88,
            description="ML predicted name",
        )
        # Rule detector identifies CRITICAL password
        secret_finding = DetectionFinding(
            entity_type=EntityType.PASSWORD,
            start=15,
            end=35,
            severity=Severity.CRITICAL,
            rule_id="secret:password_assignment",
            confidence=0.99,
            description="Assigned password credential",
        )

        resolved = resolve_overlaps([ml_finding, secret_finding])
        assert len(resolved) == 1
        assert resolved[0].entity_type == EntityType.PASSWORD
        assert resolved[0].severity == Severity.CRITICAL

    def test_deterministic_source_priority_on_equal_severity(self):
        # Two overlapping findings with equal severity (MEDIUM):
        # 1. Deterministic regex email rule (source priority 3)
        # 2. ML predicted email (source priority 1)
        rule_email = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=5,
            end=25,
            severity=Severity.MEDIUM,
            rule_id="regex:email_rfc5322",
            confidence=0.98,
            description="RFC email",
        )
        ml_email = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=5,
            end=25,
            severity=Severity.MEDIUM,
            rule_id="ml:spacy_ner:email",
            confidence=0.85,
            description="ML email",
        )

        resolved = resolve_overlaps([ml_email, rule_email])
        assert len(resolved) == 1
        # Rule-based detection wins tie-break
        assert resolved[0].rule_id == "regex:email_rfc5322"

    def test_non_overlapping_union_preserved(self):
        # Rule finds an email, ML finds a student name in a different part of the sentence
        rule_finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=0,
            end=16,
            severity=Severity.MEDIUM,
            rule_id="regex:email_rfc5322",
            confidence=0.98,
            description="Rule email",
        )
        ml_finding = DetectionFinding(
            entity_type=EntityType.NAME,
            start=30,
            end=42,
            severity=Severity.MEDIUM,
            rule_id="ml:spacy_ner:name",
            confidence=0.85,
            description="ML name",
        )

        resolved = resolve_overlaps([rule_finding, ml_finding])
        assert len(resolved) == 2
        assert resolved[0].entity_type == EntityType.EMAIL
        assert resolved[1].entity_type == EntityType.NAME

    def test_rules_only_fallback_in_detector(self):
        # Explicitly configure rules-only mode
        disabled_ml = MLPIIDetector(enabled=False)
        detector = Detector(ml_detector=disabled_ml)
        assert detector.is_ml_available is False

        text = "Contact support@example.com with password='AdminSecret123#'."
        findings = detector.detect(text)
        assert len(findings) == 2
        types = {f.entity_type for f in findings}
        assert EntityType.EMAIL in types
        assert EntityType.PASSWORD in types

    def test_ml_runtime_failure_does_not_break_rules(self, monkeypatch):
        # Mock ML detector to throw an exception
        class BuggyMLDetector:
            def is_available(self):
                return True

            def detect(self, text):
                raise RuntimeError("Simulated crash in ML backend")

        detector = Detector(ml_detector=BuggyMLDetector())
        text = "Contact user@example.com."
        findings = detector.detect(text)
        # Rule-based email detection must still execute and return findings
        assert len(findings) == 1
        assert findings[0].entity_type == EntityType.EMAIL
