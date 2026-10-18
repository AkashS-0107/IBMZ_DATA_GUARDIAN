"""Automated tests for reversible redaction and in-memory vault in redactor.py."""

import pytest
from detector import Detector
from redactor import RedactionSession, Redactor
from models import DetectionFinding, EntityType, Severity


class TestRedactor:
    """Unit and integration tests for reversible redaction pipeline."""

    @pytest.fixture
    def detector(self):
        return Detector()

    def test_successful_masking_and_restoration(self, detector):
        session = RedactionSession()
        text = "Please reach out to support@example.com regarding order."
        findings = detector.detect(text)

        result = session.redact(text, findings)
        assert "[EMAIL_1]" in result.masked_text
        assert "support@example.com" not in result.masked_text
        assert result.placeholders_count == 1

        # Simulate external AI response quoting placeholder
        ai_resp = "We have received the ticket for [EMAIL_1] and will follow up."
        restored = session.restore(ai_resp)
        assert "support@example.com" in restored
        assert "[EMAIL_1]" not in restored

    def test_preservation_of_surrounding_text(self, detector):
        session = RedactionSession()
        text = "PREFIX >>> user@example.com <<< SUFFIX"
        findings = detector.detect(text)

        result = session.redact(text, findings)
        assert result.masked_text == "PREFIX >>> [EMAIL_1] <<< SUFFIX"

        restored = session.restore(result.masked_text)
        assert restored == text

    def test_duplicate_values_receive_identical_placeholder(self, detector):
        session = RedactionSession()
        text = "Primary contact is alice@example.com and secondary contact is alice@example.com."
        findings = detector.detect(text)
        assert len(findings) == 2

        result = session.redact(text, findings)
        # Both occurrences should map to [EMAIL_1]
        assert result.masked_text.count("[EMAIL_1]") == 2
        assert "[EMAIL_2]" not in result.masked_text
        assert result.unique_placeholders == 1

        # Restores both occurrences cleanly
        restored = session.restore(result.masked_text)
        assert restored == text

    def test_literal_placeholder_collision_resistance(self, detector):
        session = RedactionSession()
        # Input text already has literal "[EMAIL_1]" written by user!
        text = "User wrote literal [EMAIL_1] and real address is actual@example.com."
        findings = detector.detect(text)
        assert len(findings) == 1
        assert findings[0].entity_type == EntityType.EMAIL

        result = session.redact(text, findings)
        # Should not collide with [EMAIL_1], so it assigns [EMAIL_2]
        assert "[EMAIL_1]" in result.masked_text
        assert "[EMAIL_2]" in result.masked_text
        assert result.masked_text == "User wrote literal [EMAIL_1] and real address is [EMAIL_2]."

        # Restoring replaces only [EMAIL_2] while keeping user's literal [EMAIL_1] intact!
        restored = session.restore(result.masked_text)
        assert restored == text

    def test_unknown_placeholders_left_unchanged(self):
        session = RedactionSession()
        # Session has no mappings
        response_with_unknown = "The model produced [EMAIL_99] and [UNKNOWN_TOKEN_1]."
        restored = session.restore(response_with_unknown)
        assert restored == response_with_unknown

    def test_malformed_and_edge_case_responses(self):
        session = RedactionSession()
        # Incomplete brackets, empty string, symbols
        assert session.restore("") == ""
        assert session.restore("Text with [EMAIL_ and [123] only.") == "Text with [EMAIL_ and [123] only."

    def test_session_isolation(self, detector):
        redactor = Redactor()
        session_a = redactor.get_or_create_session("session_a")
        session_b = redactor.get_or_create_session("session_b")

        text_a = "Contact alice@example.com"
        findings_a = detector.detect(text_a)
        res_a = session_a.redact(text_a, findings_a)

        # Session B cannot restore placeholders generated in Session A
        cross_restored = session_b.restore(res_a.masked_text)
        assert "[EMAIL_1]" in cross_restored
        assert "alice@example.com" not in cross_restored

        # Session A restores correctly
        valid_restored = session_a.restore(res_a.masked_text)
        assert "alice@example.com" in valid_restored

    def test_clearing_session_vault(self, detector):
        session = RedactionSession()
        text = "Key: password='SecretPassword123'"
        findings = detector.detect(text)
        res = session.redact(text, findings)
        assert session.active_placeholder_count == 1

        session.clear()
        assert session.active_placeholder_count == 0

        # Restoration after clear leaves placeholders intact
        attempt = session.restore(res.masked_text)
        assert "[PASSWORD_1]" in attempt
        assert "SecretPassword123" not in attempt


class TestRedactorRegressions:
    """Regression tests for edge cases and defect fixes in redactor.py."""

    def test_overlapping_findings_safely_resolved_without_mangling(self):
        session = RedactionSession()
        text = "Confidential: user_contact_12345678"
        # Overlapping findings: [14, 26) EMAIL (Medium) and [20, 34) PASSWORD (Critical)
        f_med = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=14,
            end=26,
            severity=Severity.MEDIUM,
            rule_id="test:email",
            description="Medium finding",
        )
        f_crit = DetectionFinding(
            entity_type=EntityType.PASSWORD,
            start=20,
            end=34,
            severity=Severity.CRITICAL,
            rule_id="test:pwd",
            description="Critical finding",
        )
        result = session.redact(text, [f_med, f_crit])
        # Critical finding must win and replace cleanly
        assert "[PASSWORD_1]" in result.masked_text
        assert "[EMAIL_1]" not in result.masked_text
        # Prefix "Confidential: user_c" and suffix "8" must be preserved intact without corruption
        assert result.masked_text == "Confidential: user_c[PASSWORD_1]8"
        # Restoration recovers the exact original text
        restored = session.restore(result.masked_text)
        assert restored == text

    def test_restore_detailed_audit_reporting(self):
        session = RedactionSession()
        text = "Contact alice@example.com for access."
        finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=8,
            end=25,
            severity=Severity.MEDIUM,
            rule_id="regex:email",
            description="Email",
        )
        session.redact(text, [finding])

        # 1. Fully restored response
        resp_known = "Follow up with [EMAIL_1] immediately."
        res_audit = session.restore_detailed(resp_known)
        assert res_audit.is_fully_restored is True
        assert res_audit.restored_placeholders == ["[EMAIL_1]"]
        assert res_audit.unrestored_placeholders == []
        assert "alice@example.com" in res_audit.restored_text

        # 2. Response with unknown/unowned placeholder
        resp_unknown = "Notify [EMAIL_1] and unknown agent [AGENT_TOKEN_99]."
        res_partial = session.restore_detailed(resp_unknown)
        assert res_partial.is_fully_restored is False
        assert "[EMAIL_1]" in res_partial.restored_placeholders
        assert "[AGENT_TOKEN_99]" in res_partial.unrestored_placeholders
        assert "[AGENT_TOKEN_99]" in res_partial.restored_text

    def test_restore_detailed_after_session_cleared(self):
        session = RedactionSession()
        text = "Pass: SuperSecret123"
        finding = DetectionFinding(
            entity_type=EntityType.PASSWORD,
            start=6,
            end=20,
            severity=Severity.CRITICAL,
            rule_id="test:pwd",
            description="Password",
        )
        redaction = session.redact(text, [finding])
        session.clear()

        audit = session.restore_detailed(redaction.masked_text)
        assert audit.is_fully_restored is False
        assert "[PASSWORD_1]" in audit.unrestored_placeholders
        assert audit.restored_placeholders == []
        assert "[PASSWORD_1]" in audit.restored_text

    def test_adjacent_findings_redaction_and_restoration(self):
        session = RedactionSession()
        text = "user@example.com+18005550199"
        f1 = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=0,
            end=16,
            severity=Severity.MEDIUM,
            rule_id="r1",
            description="Email",
        )
        f2 = DetectionFinding(
            entity_type=EntityType.PHONE,
            start=16,
            end=28,
            severity=Severity.HIGH,
            rule_id="r2",
            description="Phone",
        )
        redaction = session.redact(text, [f1, f2])
        assert redaction.masked_text == "[EMAIL_1][PHONE_1]"

        restored = session.restore(redaction.masked_text)
        assert restored == text

    def test_unicode_and_non_ascii_characters(self):
        session = RedactionSession()
        text = "Заказ #42: contact élève test@example.com avec succès."
        finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=25,
            end=41,
            severity=Severity.MEDIUM,
            rule_id="r1",
            description="Email",
        )
        redaction = session.redact(text, [finding])
        assert "[EMAIL_1]" in redaction.masked_text
        assert "Заказ #42: contact élève [EMAIL_1] avec succès." == redaction.masked_text

        restored = session.restore(redaction.masked_text)
        assert restored == text

    def test_out_of_bounds_finding_rejected_safely(self):
        session = RedactionSession()
        text = "Short text"
        finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=0,
            end=50,  # exceeds len(text) == 10
            severity=Severity.MEDIUM,
            rule_id="r1",
            description="Email",
        )
        with pytest.raises(ValueError) as exc:
            session.redact(text, [finding])
        assert "out of bounds" in str(exc.value)

    def test_redactor_manager_delegation(self):
        redactor = Redactor()
        session = redactor.get_or_create_session("sess_mgr_test")
        text = "Ping test@example.com now"
        finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=5,
            end=21,
            severity=Severity.MEDIUM,
            rule_id="r1",
            description="Email",
        )
        redaction = session.redact(text, [finding])

        restored_str = redactor.restore("sess_mgr_test", redaction.masked_text)
        assert "test@example.com" in restored_str

        audit = redactor.restore_detailed("sess_mgr_test", redaction.masked_text)
        assert audit.is_fully_restored is True
        assert "[EMAIL_1]" in audit.restored_placeholders

