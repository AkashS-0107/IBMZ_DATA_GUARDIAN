"""Automated tests for deterministic risk assessment in risk.py."""

import pytest
from models import DetectionFinding, EntityType, Severity
from risk import assess_risk


class TestRiskAssessment:
    """Unit tests for the 4-tier exposure risk engine."""

    def test_low_risk_clean_text(self):
        assessment = assess_risk([])
        assert assessment.risk_level == Severity.LOW
        assert assessment.findings_count == 0
        assert len(assessment.reasons) > 0
        assert "No sensitive personal information" in assessment.reasons[0]

    def test_low_risk_only_public_url(self):
        finding = DetectionFinding(
            entity_type=EntityType.PERSONAL_URL,
            start=10,
            end=35,
            severity=Severity.LOW,
            rule_id="regex:personal_profile_url",
            description="Detected personal URL",
        )
        assessment = assess_risk([finding])
        assert assessment.risk_level == Severity.LOW
        assert assessment.low_count == 1
        assert "Only 1 low-risk" in assessment.reasons[0]

    def test_medium_risk_single_pii(self):
        finding = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=5,
            end=25,
            severity=Severity.MEDIUM,
            rule_id="regex:email_rfc5322",
            description="Detected email",
        )
        assessment = assess_risk([finding])
        assert assessment.risk_level == Severity.MEDIUM
        assert assessment.medium_count == 1
        assert "Exactly one isolated personal identifier" in assessment.reasons[0]

    def test_high_risk_multiple_medium_pii(self):
        # 2 emails combined -> aggregated re-identification risk -> HIGH
        f1 = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=0,
            end=18,
            severity=Severity.MEDIUM,
            rule_id="regex:email_rfc5322",
            description="Detected email 1",
        )
        f2 = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=25,
            end=45,
            severity=Severity.MEDIUM,
            rule_id="regex:email_rfc5322",
            description="Detected email 2",
        )
        assessment = assess_risk([f1, f2])
        assert assessment.risk_level == Severity.HIGH
        assert assessment.medium_count == 2
        assert "Multiple (2) Medium-severity PII findings" in assessment.reasons[0]

    def test_high_risk_direct_high_consequence_pii(self):
        # SSN or Phone number
        f_ssn = DetectionFinding(
            entity_type=EntityType.ID_NUMBER,
            start=10,
            end=21,
            severity=Severity.HIGH,
            rule_id="regex:ssn_formatted",
            description="Detected SSN",
        )
        assessment = assess_risk([f_ssn])
        assert assessment.risk_level == Severity.HIGH
        assert assessment.high_count == 1
        assert "HIGH: Detected 1 high-consequence finding" in assessment.reasons[0]

    def test_critical_risk_secret_priority(self):
        # Even with low and medium findings, any critical credential forces CRITICAL
        f_low = DetectionFinding(
            entity_type=EntityType.PERSONAL_URL,
            start=0,
            end=20,
            severity=Severity.LOW,
            rule_id="regex:url",
            description="Profile URL",
        )
        f_med = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=25,
            end=45,
            severity=Severity.MEDIUM,
            rule_id="regex:email",
            description="Email address",
        )
        f_crit = DetectionFinding(
            entity_type=EntityType.PASSWORD,
            start=50,
            end=70,
            severity=Severity.CRITICAL,
            rule_id="secret:password",
            description="Password credential",
        )
        assessment = assess_risk([f_low, f_med, f_crit])
        assert assessment.risk_level == Severity.CRITICAL
        assert assessment.critical_count == 1
        assert "CRITICAL: Detected 1 confirmed credential" in assessment.reasons[0]
        assert any("Secondary findings present" in r for r in assessment.reasons)


class TestRiskAssessmentRegressions:
    """Regression tests for edge cases and defect fixes in risk.py."""

    def test_high_entropy_secret_triggers_high_risk(self):
        f = DetectionFinding(
            entity_type=EntityType.HIGH_ENTROPY_SECRET,
            start=10,
            end=35,
            severity=Severity.HIGH,
            rule_id="heuristic:shannon_entropy",
            description="High entropy token",
        )
        assessment = assess_risk([f])
        assert assessment.risk_level == Severity.HIGH
        assert assessment.high_count == 1
        assert "HIGH: Detected 1 high-consequence finding" in assessment.reasons[0]

    def test_private_key_triggers_critical_risk(self):
        f = DetectionFinding(
            entity_type=EntityType.PRIVATE_KEY,
            start=0,
            end=120,
            severity=Severity.CRITICAL,
            rule_id="secret:private_key",
            description="Private key block",
        )
        assessment = assess_risk([f])
        assert assessment.risk_level == Severity.CRITICAL
        assert assessment.critical_count == 1
        assert "CRITICAL: Detected 1 confirmed credential" in assessment.reasons[0]

    def test_overlapping_findings_do_not_inflate_risk_counts(self):
        # Overlapping findings: [10, 25) IP_ADDRESS (Medium) and [5, 30) API_KEY (Critical)
        f_med = DetectionFinding(
            entity_type=EntityType.IP_ADDRESS,
            start=10,
            end=25,
            severity=Severity.MEDIUM,
            rule_id="regex:ip",
            description="IP address",
        )
        f_crit = DetectionFinding(
            entity_type=EntityType.API_KEY,
            start=5,
            end=30,
            severity=Severity.CRITICAL,
            rule_id="secret:api_key",
            description="API Key",
        )
        assessment = assess_risk([f_med, f_crit])
        # Overlap resolution must keep only the Critical API_KEY
        assert assessment.risk_level == Severity.CRITICAL
        assert assessment.critical_count == 1
        assert assessment.medium_count == 0
        assert assessment.findings_count == 1

    def test_multi_severity_combination_precedence(self):
        f_low = DetectionFinding(
            entity_type=EntityType.PERSONAL_URL,
            start=0,
            end=20,
            severity=Severity.LOW,
            rule_id="r1",
            description="URL",
        )
        f_med = DetectionFinding(
            entity_type=EntityType.EMAIL,
            start=25,
            end=45,
            severity=Severity.MEDIUM,
            rule_id="r2",
            description="Email",
        )
        f_high = DetectionFinding(
            entity_type=EntityType.PHONE,
            start=50,
            end=65,
            severity=Severity.HIGH,
            rule_id="r3",
            description="Phone",
        )
        f_crit = DetectionFinding(
            entity_type=EntityType.DB_CREDENTIAL,
            start=70,
            end=120,
            severity=Severity.CRITICAL,
            rule_id="r4",
            description="DB",
        )
        assessment = assess_risk([f_low, f_med, f_high, f_crit])
        assert assessment.risk_level == Severity.CRITICAL
        assert assessment.critical_count == 1
        assert assessment.high_count == 1
        assert assessment.medium_count == 1
        assert assessment.low_count == 1
        assert assessment.findings_count == 4
        # Explanation includes secondary findings notice
        assert any("Secondary findings present: 1 High-severity and 1 Medium-severity" in r for r in assessment.reasons)

