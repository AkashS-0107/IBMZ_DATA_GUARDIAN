"""Automated unit and integration tests for detector.py."""

import pytest
from config import DetectorConfig
from detector import Detector, calculate_shannon_entropy, resolve_overlaps
from models import DetectionFinding, EntityType, Severity


class TestShannonEntropy:
    """Tests for Shannon entropy calculation and candidate heuristics."""

    def test_empty_string(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_single_character_and_short_strings(self):
        assert calculate_shannon_entropy("a") == 0.0
        assert calculate_shannon_entropy("aaaaaa") == 0.0
        # "ab" length 2: two equal characters -> 1.0 bit
        assert calculate_shannon_entropy("ab") == 1.0

    def test_low_entropy_strings(self):
        # Repetitive pattern
        low_entropy = calculate_shannon_entropy("abcabcabcabcabcabc")
        assert low_entropy < 2.0

    def test_high_entropy_strings(self):
        # 16 distinct characters uniformly distributed
        high_entropy = calculate_shannon_entropy("0123456789abcdef")
        assert high_entropy == 4.0
        # Highly random token
        random_token = "9fAkL2vP9zW8qM1b7Xy4"
        assert calculate_shannon_entropy(random_token) >= 3.6


class TestPIIDetection:
    """Tests for all supported PII categories."""

    @pytest.fixture
    def detector(self):
        return Detector()

    def test_email_detection(self, detector):
        text = "Contact us at security-team@example.org or admin@sub.domain.co.uk."
        findings = detector.detect(text)
        emails = [f for f in findings if f.entity_type == EntityType.EMAIL]
        assert len(emails) == 2
        assert text[emails[0].start:emails[0].end] == "security-team@example.org"
        assert text[emails[1].start:emails[1].end] == "admin@sub.domain.co.uk"
        assert emails[0].severity == Severity.MEDIUM

    def test_phone_detection_international_formats(self, detector):
        text = "Call US +1-800-555-0199 or UK +44 20 7946 0991 or direct 0123456789."
        findings = detector.detect(text)
        phones = [f for f in findings if f.entity_type == EntityType.PHONE]
        assert len(phones) >= 2
        values = [text[p.start:p.end] for p in phones]
        assert "+1-800-555-0199" in values
        assert "+44 20 7946 0991" in values
        assert phones[0].severity == Severity.HIGH

    def test_ipv4_and_ipv6_detection(self, detector):
        text = "Connect to 192.168.1.1 or 10.0.0.254 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334."
        findings = detector.detect(text)
        ips = [f for f in findings if f.entity_type == EntityType.IP_ADDRESS]
        assert len(ips) >= 2
        values = [text[ip.start:ip.end] for ip in ips]
        assert "192.168.1.1" in values
        assert "10.0.0.254" in values

    def test_personal_url_detection(self, detector):
        text = "Profiles: https://linkedin.com/in/test-user and https://github.com/developer-mock."
        findings = detector.detect(text)
        urls = [f for f in findings if f.entity_type == EntityType.PERSONAL_URL]
        assert len(urls) == 2
        assert text[urls[0].start:urls[0].end] == "https://linkedin.com/in/test-user"
        assert text[urls[1].start:urls[1].end] == "https://github.com/developer-mock"
        assert urls[0].severity == Severity.LOW

    def test_id_number_ssn_detection(self, detector):
        text = "ID recorded: 000-12-3456 in application file."
        findings = detector.detect(text)
        ids = [f for f in findings if f.entity_type == EntityType.ID_NUMBER]
        assert len(ids) == 1
        assert text[ids[0].start:ids[0].end] == "000-12-3456"
        assert ids[0].severity == Severity.HIGH

    def test_contextual_name_detection(self, detector):
        text = "Patient Name: Alice Walker visited Dr. Bob Smith yesterday."
        findings = detector.detect(text)
        names = [f for f in findings if f.entity_type == EntityType.NAME]
        assert len(names) >= 1
        name_vals = [text[n.start:n.end] for n in names]
        assert "Alice Walker" in name_vals


class TestSecretDetection:
    """Tests for passwords, tokens, API keys, private keys, and connection strings."""

    @pytest.fixture
    def detector(self):
        return Detector()

    def test_password_assignment(self, detector):
        text = 'Server setting: password="SuperSecretP@ss123" confirmed.'
        findings = detector.detect(text)
        passwords = [f for f in findings if f.entity_type == EntityType.PASSWORD]
        assert len(passwords) == 1
        assert text[passwords[0].start:passwords[0].end] == "SuperSecretP@ss123"
        assert passwords[0].severity == Severity.CRITICAL

    def test_bearer_token(self, detector):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummySig"
        findings = detector.detect(text)
        tokens = [f for f in findings if f.entity_type == EntityType.BEARER_TOKEN]
        assert len(tokens) == 1
        assert text[tokens[0].start:tokens[0].end] == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummySig"
        assert tokens[0].severity == Severity.CRITICAL

    def test_database_connection_string(self, detector):
        text = "URI: postgresql://admin:StrongPass99@db.prod.internal:5432/main_db"
        findings = detector.detect(text)
        db_creds = [f for f in findings if f.entity_type == EntityType.DB_CREDENTIAL]
        assert len(db_creds) == 1
        assert text[db_creds[0].start:db_creds[0].end] == "postgresql://admin:StrongPass99@db.prod.internal:5432/main_db"
        assert db_creds[0].severity == Severity.CRITICAL

    def test_cloud_credentials(self, detector):
        # AWS Key
        text_aws = "Deploy with key AKIAIOSFODNN7EXAMPLE today."
        findings_aws = detector.detect(text_aws)
        assert any(f.entity_type == EntityType.CLOUD_CREDENTIAL for f in findings_aws)

        # GitHub token
        text_gh = "Set token ghp_dummyGitHubPersonalAccessToken1234567890."
        findings_gh = detector.detect(text_gh)
        assert any(f.entity_type == EntityType.CLOUD_CREDENTIAL for f in findings_gh)

    def test_private_key_block(self, detector):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6dummy\n"
            "-----END PRIVATE KEY-----"
        )
        text = f"Key material:\n{pem}\nEnd of secret."
        findings = detector.detect(text)
        pkeys = [f for f in findings if f.entity_type == EntityType.PRIVATE_KEY]
        assert len(pkeys) == 1
        assert text[pkeys[0].start:pkeys[0].end] == pem
        assert pkeys[0].severity == Severity.CRITICAL


class TestOverlapAndOrderingQuality:
    """Tests for overlap resolution, deterministic ordering, and edge cases."""

    @pytest.fixture
    def detector(self):
        return Detector()

    def test_secret_priority_over_lower_severity_pii(self, detector):
        # API key value that contains an IP address
        text = 'Overlapping secret: api_key="192.168.1.100_key" with priority.'
        findings = detector.detect(text)
        # Should detect CRITICAL API_KEY and discard the overlapping MEDIUM IP_ADDRESS
        assert len(findings) == 1
        assert findings[0].entity_type == EntityType.API_KEY
        assert findings[0].severity == Severity.CRITICAL
        assert text[findings[0].start:findings[0].end] == "192.168.1.100_key"

    def test_deterministic_ordering(self, detector):
        text = "First alice@example.com then Bob (+1-800-555-0199) and 10.0.0.1."
        findings = detector.detect(text)
        assert len(findings) >= 3
        # Offsets must be strictly non-decreasing and non-overlapping
        for i in range(len(findings) - 1):
            assert findings[i].end <= findings[i + 1].start

    def test_empty_and_whitespace_input(self, detector):
        assert detector.detect("") == []
        assert detector.detect("   \n\t   ") == []

    def test_false_positives_filtered(self, detector):
        # Standard camelCase code words and regular English
        code_text = "The AuthenticationController uses SystemConfiguration and adds addEventListener."
        findings = detector.detect(code_text)
        assert len(findings) == 0


class TestDetectorRegressions:
    """Regression tests for edge cases and defect fixes in detector.py."""

    @pytest.fixture
    def detector(self):
        return Detector()

    def test_phone_boundary_rejection_identifiers_and_uuids(self, detector):
        # UUID, git hash, and identifier numbers should NOT trigger phone detection
        text = (
            "Trace: id1234567890123 in commit a1b2c3d4e5f67890123456789abcdef012345678 "
            "with request UUID 123e4567-e89b-12d3-a456-426614174000."
        )
        findings = detector.detect(text)
        phones = [f for f in findings if f.entity_type == EntityType.PHONE]
        assert len(phones) == 0, f"Expected 0 false phones, got: {phones}"

    def test_international_phone_5_digit_grouping(self, detector):
        text = "Emergency desk: +91 98765 43210 available 24/7."
        findings = detector.detect(text)
        phones = [f for f in findings if f.entity_type == EntityType.PHONE]
        assert len(phones) == 1
        assert text[phones[0].start:phones[0].end] == "+91 98765 43210"

    def test_ipv6_loopback_and_compressed_addresses(self, detector):
        text = "Listening on ::1 (loopback) and fe80::1 (link-local), but not on time 12:30:45."
        findings = detector.detect(text)
        ips = [f for f in findings if f.entity_type == EntityType.IP_ADDRESS]
        ip_vals = [text[ip.start:ip.end] for ip in ips]
        assert "::1" in ip_vals
        assert "fe80::1" in ip_vals
        assert not any("12:30" in val for val in ip_vals)

    def test_unquoted_password_sentence_punctuation_stripped(self, detector):
        text = "Server password is password=SuperSecretP@ss123. Please note."
        findings = detector.detect(text)
        pw = [f for f in findings if f.entity_type == EntityType.PASSWORD]
        assert len(pw) == 1
        assert text[pw[0].start:pw[0].end] == "SuperSecretP@ss123"

    def test_quoted_password_preserves_internal_punctuation(self, detector):
        text = 'Setting: password="SuperSecretP@ss123." confirmed.'
        findings = detector.detect(text)
        pw = [f for f in findings if f.entity_type == EntityType.PASSWORD]
        assert len(pw) == 1
        assert text[pw[0].start:pw[0].end] == "SuperSecretP@ss123."

    def test_unquoted_api_key_sentence_punctuation_stripped(self, detector):
        text = "Key recorded: api_key=sk_live_1234567890abcdef. Done."
        findings = detector.detect(text)
        keys = [f for f in findings if f.entity_type == EntityType.API_KEY]
        assert len(keys) == 1
        assert text[keys[0].start:keys[0].end] == "sk_live_1234567890abcdef"

    def test_database_connection_string_sentence_punctuation_stripped(self, detector):
        text = "Connect to postgresql://user:pass@localhost:5432/core_db. Service ready."
        findings = detector.detect(text)
        dbs = [f for f in findings if f.entity_type == EntityType.DB_CREDENTIAL]
        assert len(dbs) == 1
        assert text[dbs[0].start:dbs[0].end] == "postgresql://user:pass@localhost:5432/core_db"

    def test_base64_high_entropy_token_padding(self, detector):
        text = "Base64 token: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY== stored."
        findings = detector.detect(text)
        secrets = [f for f in findings if f.entity_type == EntityType.HIGH_ENTROPY_SECRET]
        assert len(secrets) == 1
        assert text[secrets[0].start:secrets[0].end] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY=="

    def test_high_entropy_secret_not_suppressed_by_medium_pii(self, detector):
        text = "System secret token: 192.168.1.1_abcD3fGh9JkLmN2P8 generated."
        findings = detector.detect(text)
        # High entropy secret should be detected
        assert any(f.entity_type == EntityType.HIGH_ENTROPY_SECRET for f in findings)

    def test_invalid_input_types_raise_type_error(self, detector):
        with pytest.raises(TypeError) as exc:
            detector.detect(12345)
        assert "must be a string" in str(exc.value)

    def test_configurable_entropy_threshold(self):
        custom_config = DetectorConfig()
        custom_config.MIN_SHANNON_ENTROPY = 4.5
        strict_detector = Detector(config=custom_config)
        # Moderate entropy token (~4.2 bits) should be filtered under 4.5 threshold
        text = "Encountered session token 9fAkL2vP9zW8qM1b7Xy4 inside debugging logs."
        findings = strict_detector.detect(text)
        assert not any(f.entity_type == EntityType.HIGH_ENTROPY_SECRET for f in findings)

