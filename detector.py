"""Sensitive data detection engine for AI Data Leak Guardian.

Implements detection for PII (email, phone, IP addresses, names, URLs, IDs)
and secrets (passwords, API keys, bearer tokens, DB strings, private keys, cloud tokens)
along with Shannon entropy heuristic analysis and deterministic overlap resolution.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
import math
import re
from typing import List, Optional, Set

from config import DetectorConfig
from models import DetectionFinding, EntityType, Severity


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    H(X) = -sum(p(x) * log2(p(x)))
    Returns 0.0 for empty or single-character strings.
    """
    if not data or len(data) <= 1:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


class PIIDetector:
    """Detects personally identifiable information (PII) using robust rules."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()

    def detect(self, text: str) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        # 1. Emails
        for match in self.config.EMAIL_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.EMAIL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.EMAIL],
                    rule_id="regex:email_rfc5322",
                    confidence=0.98,
                    description=f"Detected email address (length {end - start})",
                )
            )

        # 2. International Phone Numbers
        for match in self.config.PHONE_PATTERN.finditer(text):
            raw_val = match.group(0).strip()
            # Clean digits only to verify realistic phone length (7 to 15 digits according to E.164)
            digits = re.sub(r"\D", "", raw_val)
            if 7 <= len(digits) <= 15:
                start, end = match.start(), match.end()
                findings.append(
                    DetectionFinding(
                        entity_type=EntityType.PHONE,
                        start=start,
                        end=end,
                        severity=self.config.ENTITY_SEVERITY[EntityType.PHONE],
                        rule_id="regex:phone_e164",
                        confidence=0.90,
                        description=f"Detected telephone number (length {end - start})",
                    )
                )

        # 3. IPv4 Addresses
        for match in self.config.IPV4_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.IP_ADDRESS,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.IP_ADDRESS],
                    rule_id="regex:ipv4_octet",
                    confidence=0.95,
                    description="Detected IPv4 network address",
                )
            )

        # 4. IPv6 Addresses
        for match in self.config.IPV6_PATTERN.finditer(text):
            val = match.group(0)
            if ":" in val:
                try:
                    ipaddress.IPv6Address(val)
                except ValueError:
                    continue
                start, end = match.start(), match.end()
                findings.append(
                    DetectionFinding(
                        entity_type=EntityType.IP_ADDRESS,
                        start=start,
                        end=end,
                        severity=self.config.ENTITY_SEVERITY[EntityType.IP_ADDRESS],
                        rule_id="regex:ipv6_colon",
                        confidence=0.92,
                        description="Detected IPv6 network address",
                    )
                )

        # 5. Personal Profile URLs
        for match in self.config.PERSONAL_URL_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.PERSONAL_URL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.PERSONAL_URL],
                    rule_id="regex:personal_profile_url",
                    confidence=0.95,
                    description="Detected personal profile URL",
                )
            )

        # 6. US SSN / Identity Number
        for match in self.config.ID_NUMBER_SSN_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.ID_NUMBER,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.ID_NUMBER],
                    rule_id="regex:ssn_formatted",
                    confidence=0.92,
                    description="Detected government identity number (SSN format)",
                )
            )

        # 7. Contextual Name Detection
        for match in self.config.NAME_CONTEXT_PATTERN.finditer(text):
            # Extract only the name span (group 1), preserving the cue prefix
            start, end = match.start(1), match.end(1)
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.NAME,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.NAME],
                    rule_id="context:name_honorific",
                    confidence=0.85,
                    description="Detected person name via context marker",
                )
            )

        return findings


class SecretDetector:
    """Detects credentials, API keys, private keys, and connection strings."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()

    def detect(self, text: str) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        # 1. Password assignments: extract matched password value
        for match in self.config.PASSWORD_ASSIGNMENT_PATTERN.finditer(text):
            if match.group("q_val") is not None:
                start, end = match.start("q_val"), match.end("q_val")
            else:
                start, end = match.start("raw_val"), match.end("raw_val")
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.PASSWORD,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.PASSWORD],
                    rule_id="secret:password_assignment",
                    confidence=0.99,
                    description="Detected assigned password credential",
                )
            )

        # 2. Bearer tokens: match group 1 is the token
        for match in self.config.BEARER_TOKEN_PATTERN.finditer(text):
            start, end = match.start(1), match.end(1)
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.BEARER_TOKEN,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.BEARER_TOKEN],
                    rule_id="secret:bearer_token_header",
                    confidence=0.98,
                    description="Detected HTTP Bearer authorization token",
                )
            )

        # 3. Generic API key assignments: extract matched key value
        for match in self.config.GENERIC_API_KEY_PATTERN.finditer(text):
            if match.group("q_val") is not None:
                start, end = match.start("q_val"), match.end("q_val")
            else:
                start, end = match.start("raw_val"), match.end("raw_val")
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.API_KEY,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.API_KEY],
                    rule_id="secret:api_key_assignment",
                    confidence=0.95,
                    description="Detected API key or secret token assignment",
                )
            )

        # 4. Database connection strings (entire URI)
        for match in self.config.DB_CONNECTION_STRING_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.DB_CREDENTIAL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.DB_CREDENTIAL],
                    rule_id="secret:db_connection_uri",
                    confidence=0.99,
                    description="Detected database connection string with credentials",
                )
            )

        # 5. Private Key blocks (entire PEM block)
        for match in self.config.PRIVATE_KEY_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.PRIVATE_KEY,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.PRIVATE_KEY],
                    rule_id="secret:private_key_pem",
                    confidence=1.0,
                    description="Detected cryptographic private key block",
                )
            )

        # 6. AWS Access Keys
        for match in self.config.AWS_ACCESS_KEY_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.CLOUD_CREDENTIAL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.CLOUD_CREDENTIAL],
                    rule_id="secret:aws_access_key",
                    confidence=0.98,
                    description="Detected AWS cloud access key ID",
                )
            )

        # 7. GitHub Tokens
        for match in self.config.GITHUB_TOKEN_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.CLOUD_CREDENTIAL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.CLOUD_CREDENTIAL],
                    rule_id="secret:github_personal_token",
                    confidence=0.99,
                    description="Detected GitHub personal access token",
                )
            )

        # 8. Slack Tokens
        for match in self.config.SLACK_TOKEN_PATTERN.finditer(text):
            start, end = match.start(), match.end()
            findings.append(
                DetectionFinding(
                    entity_type=EntityType.CLOUD_CREDENTIAL,
                    start=start,
                    end=end,
                    severity=self.config.ENTITY_SEVERITY[EntityType.CLOUD_CREDENTIAL],
                    rule_id="secret:slack_token",
                    confidence=0.99,
                    description="Detected Slack API token",
                )
            )

        return findings


class EntropyDetector:
    """Heuristic detector identifying high-entropy candidate secrets."""

    # Candidate token regex: alphanumeric, base64, hex, or hyphenated tokens with clean boundaries
    CANDIDATE_TOKEN_PATTERN: re.Pattern = re.compile(
        r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/=_\-]{16,256}(?![A-Za-z0-9+/=_\-])"
    )

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        self._pattern = re.compile(
            rf"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/=_\-]{{{self.config.MIN_ENTROPY_LENGTH},{self.config.MAX_ENTROPY_LENGTH}}}(?![A-Za-z0-9+/=_\-])"
        )

    def detect(self, text: str, existing_spans: Optional[List[DetectionFinding]] = None) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        existing = existing_spans or []

        for match in self._pattern.finditer(text):
            start, end = match.start(), match.end()
            candidate = match.group(0)

            # Skip if already inside a known higher-severity detected secret (Critical credentials)
            # This ensures lower-severity findings (Medium PII) never silently suppress High-Entropy secrets
            if any(max(start, e.start) < min(end, e.end) for e in existing if e.severity.rank > Severity.HIGH.rank):
                continue

            # Length bounds check
            if not (self.config.MIN_ENTROPY_LENGTH <= len(candidate) <= self.config.MAX_ENTROPY_LENGTH):
                continue

            # Exclude known programming keywords and English identifiers
            if candidate.lower() in self.config.EXCLUDED_ENTROPY_WORDS:
                continue

            # Diversity heuristic: candidate must not be all lowercase or all uppercase without digits
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            has_symbol = any(c in "+/=_-." for c in candidate)
            variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
            if variety_count < 2:
                continue

            # Unique character ratio check
            unique_ratio = len(set(candidate)) / len(candidate)
            if unique_ratio < self.config.MIN_UNIQUE_CHAR_RATIO:
                continue

            # Shannon entropy calculation
            entropy = calculate_shannon_entropy(candidate)
            if entropy >= self.config.MIN_SHANNON_ENTROPY:
                findings.append(
                    DetectionFinding(
                        entity_type=EntityType.HIGH_ENTROPY_SECRET,
                        start=start,
                        end=end,
                        severity=self.config.ENTITY_SEVERITY[EntityType.HIGH_ENTROPY_SECRET],
                        rule_id="heuristic:shannon_entropy",
                        confidence=min(1.0, 0.70 + (entropy - self.config.MIN_SHANNON_ENTROPY) * 0.15),
                        description=f"High-entropy candidate secret token (H={entropy:.2f} bits/char)",
                        metadata={"entropy": entropy, "length": len(candidate)},
                    )
                )

        return findings


def _source_priority(rule_id: str) -> int:
    """Assign deterministic source precedence for resolving ties with equal severity."""
    if rule_id.startswith(("secret:", "regex:")):
        return 3
    elif rule_id.startswith("context:"):
        return 2
    elif rule_id.startswith("ml:"):
        return 1
    return 0


def resolve_overlaps(findings: List[DetectionFinding]) -> List[DetectionFinding]:
    """Resolve overlapping detections deterministically.

    Policy:
    1. Higher severity takes strict precedence over lower severity.
       (Ensures Critical secrets are never discarded for Medium/Low PII).
    2. When severities are equal, source priority breaks ties:
       deterministic rules (secret/regex) > contextual rules > ML predictions > entropy.
    3. If severities and sources are equal, longer span wins.
    4. If still equal, earlier start offset wins.
    Returns non-overlapping findings sorted strictly by start offset ascending.
    """
    if not findings:
        return []

    # Sort priority:
    # 1. Severity rank descending (-f.severity.rank)
    # 2. Source priority descending (-_source_priority(f.rule_id))
    # 3. Span length descending (-f.span_length)
    # 4. Start offset ascending (f.start)
    candidates = sorted(
        findings,
        key=lambda f: (-f.severity.rank, -_source_priority(f.rule_id), -f.span_length, f.start, f.end)
    )

    resolved: List[DetectionFinding] = []
    for cand in candidates:
        # Check if candidate overlaps with any already accepted finding
        if not any(cand.overlaps_with(accepted) for accepted in resolved):
            resolved.append(cand)

    # Return deterministically sorted by start offset ascending
    resolved.sort(key=lambda f: (f.start, f.end))
    return resolved


class Detector:
    """Unified hybrid detector coordinating rules, ML NER, and entropy detection."""

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        ml_detector: Optional[object] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.pii_detector = PIIDetector(self.config)
        self.secret_detector = SecretDetector(self.config)
        self.entropy_detector = EntropyDetector(self.config)

        if ml_detector is not None:
            self.ml_detector = ml_detector
        else:
            # Lazy import ML detector to avoid startup overhead or circular imports
            try:
                from training.predict import MLPIIDetector
                self.ml_detector = MLPIIDetector(
                    model_path=getattr(self.config, "ML_MODEL_PATH", "models/pii_ner"),
                    confidence_threshold=getattr(self.config, "ML_CONFIDENCE_THRESHOLD", 0.50),
                    enabled=getattr(self.config, "ML_ENABLED", True),
                    config=self.config,
                )
            except Exception:
                self.ml_detector = None

    @property
    def is_ml_available(self) -> bool:
        """Return True if the trained ML model is available and enabled."""
        return (
            self.ml_detector is not None
            and hasattr(self.ml_detector, "is_available")
            and self.ml_detector.is_available()
        )

    def detect(self, text: str) -> List[DetectionFinding]:
        """Detect sensitive entities in text and return non-overlapping findings.

        Offsets are guaranteed 0-based, half-open [start, end) within len(text).
        Combines:
        1. Rule-based secrets & credentials (Critical severity)
        2. Rule-based PII (regex and contextual)
        3. Contextual ML PII (trained spaCy NER)
        4. High-entropy candidate secrets
        """
        if text is None:
            return []
        if not isinstance(text, str):
            raise TypeError(f"Input text must be a string, got {type(text).__name__}")
        if not text.strip():
            return []

        all_findings: List[DetectionFinding] = []

        # 1. Secrets detection (highest priority patterns)
        secret_findings = self.secret_detector.detect(text)
        all_findings.extend(secret_findings)

        # 2. Rule-based PII detection
        pii_findings = self.pii_detector.detect(text)
        all_findings.extend(pii_findings)

        # 3. Contextual ML PII detection (if model is available)
        if self.is_ml_available:
            try:
                ml_findings = self.ml_detector.detect(text)
                all_findings.extend(ml_findings)
            except Exception as exc:
                # Safe audit: never allow ML failure to disable rule-based security
                import logging
                logging.getLogger("detector").warning(
                    "Safe audit: ML detector encountered runtime error (%s). Proceeding in rules-only mode.",
                    type(exc).__name__
                )

        # 4. Entropy detection (excluding existing matches)
        entropy_findings = self.entropy_detector.detect(text, existing_spans=all_findings)
        all_findings.extend(entropy_findings)

        # 5. Resolve overlaps with secret/severity priority
        clean_findings = resolve_overlaps(all_findings)

        # 6. Offset validation against original text length
        text_len = len(text)
        for f in clean_findings:
            if not (0 <= f.start < f.end <= text_len):
                raise ValueError(
                    f"Finding span [{f.start}, {f.end}) is out of bounds for text of length {text_len}"
                )

        return clean_findings
