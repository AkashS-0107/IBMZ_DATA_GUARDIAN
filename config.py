"""Configuration settings and detection rules for AI Data Leak Guardian.

Provides central definitions for regular expression patterns, entropy thresholds,
severity mappings, and redaction placeholder configurations.
"""

from __future__ import annotations

import re
from typing import Dict, List, Pattern, Set
from models import EntityType, Severity


class DetectorConfig:
    """Detection rules, regexes, and heuristic thresholds."""

    # -------------------------------------------------------------
    # PII Regular Expressions
    # -------------------------------------------------------------
    # Email: standard compliant RFC 5322 compatible pattern
    EMAIL_PATTERN: Pattern = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Phone: International formats with optional country code (+1, +44, +91 etc.),
    # area code in parens/dashes, and 7-15 digits. Uses lookbehind/lookahead to prevent
    # matching inside identifiers, UUIDs, or hex hashes.
    PHONE_PATTERN: Pattern = re.compile(
        r"(?<![\w+-\.\/])(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,5}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{3,5}(?![\w-])"
    )

    # IP Addresses: IPv4 with octet validation (0-255)
    IPV4_PATTERN: Pattern = re.compile(
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # IPv6 (RFC-compliant full, compressed, and loopback patterns)
    IPV6_PATTERN: Pattern = re.compile(
        r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|"
        r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?![0-9a-fA-F:])|"
        r"(?<![0-9a-fA-F:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|"
        r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|"
        r"(?<![0-9a-fA-F:])::(?![0-9a-fA-F:])"
    )

    # Personal URLs (social profiles, GitHub, LinkedIn)
    PERSONAL_URL_PATTERN: Pattern = re.compile(
        r"https?://(?:www\.)?(?:linkedin\.com/in/[\w-]+|github\.com/[\w-]+|"
        r"twitter\.com/[\w-]+|x\.com/[\w-]+|gitlab\.com/[\w-]+)\b"
    )

    # Identity Numbers: US SSN format (3-2-4 digits)
    ID_NUMBER_SSN_PATTERN: Pattern = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )

    # Names: Context-based detection when preceded by common titles or cue words
    # e.g., "Name: John Doe", "Student: Jane Smith", "Dr. Alan Turing"
    NAME_CONTEXT_PATTERN: Pattern = re.compile(
        r"\b(?:Name|Student|Author|Employee|Candidate|User|Dr\.|Mr\.|Ms\.|Mrs\.|Prof\.)[:\s]+"
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
    )

    # -------------------------------------------------------------
    # Credential & Secret Regular Expressions
    # -------------------------------------------------------------
    # Password assignments (supports quoted strings with spaces or unquoted values without sentence punctuation)
    PASSWORD_ASSIGNMENT_PATTERN: Pattern = re.compile(
        r"(?i)\b(?:password|passwd|pwd|pass|secret_key|api_secret)\s*[:=]\s*"
        r"(?:['\"](?P<q_val>[^'\"]{6,})['\"]|(?P<raw_val>[^\s'\",;]{6,}(?<![\.\,\;\:\?\!)])))"
    )

    # Bearer tokens in headers or text (Bearer eyJ... or Bearer <alphanumeric>)
    BEARER_TOKEN_PATTERN: Pattern = re.compile(
        r"\bBearer\s+([A-Za-z0-9_\-\.]{16,})\b"
    )

    # Generic API Keys and tokens assigned in variables
    GENERIC_API_KEY_PATTERN: Pattern = re.compile(
        r"(?i)\b(?:api_key|apikey|access_token|auth_token|client_secret|private_token)\s*[:=]\s*"
        r"(?:['\"](?P<q_val>[A-Za-z0-9_\-\.]{12,})['\"]|(?P<raw_val>[A-Za-z0-9_\-\.]{12,}(?<![\.\,\;\:\?\!)])))"
    )

    # Database connection strings with embedded credentials (excluding trailing sentence punctuation)
    DB_CONNECTION_STRING_PATTERN: Pattern = re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|redis|cockroachdb)://"
        r"(?:[^:\s]+:[^@\s]+@)[^\s'\"<>,]+(?<![\.\,\;\:\?\!)])"
    )

    # Private key markers (RSA, DSA, EC, OPENSSH, PGP)
    PRIVATE_KEY_PATTERN: Pattern = re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    )

    # Cloud Credentials:
    # AWS Access Key ID (AKIA, ASIA, etc.)
    AWS_ACCESS_KEY_PATTERN: Pattern = re.compile(
        r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b"
    )

    # GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    GITHUB_TOKEN_PATTERN: Pattern = re.compile(
        r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"
    )

    # Slack bot and user tokens (xoxb-, xoxp-, xoxa-, xoxr-)
    SLACK_TOKEN_PATTERN: Pattern = re.compile(
        r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b"
    )

    # -------------------------------------------------------------
    # Shannon Entropy Heuristic Settings
    # -------------------------------------------------------------
    MIN_ENTROPY_LENGTH: int = 16
    MAX_ENTROPY_LENGTH: int = 256
    MIN_SHANNON_ENTROPY: float = 3.6  # bits per character threshold

    # Common programming terms, identifiers, and english words to exclude from entropy detection
    EXCLUDED_ENTROPY_WORDS: Set[str] = {
        "authenticationcontroller",
        "systemconfiguration",
        "addeventlistener",
        "methodnotallowed",
        "internalservererror",
        "badrequesterror",
        "contenttypeheader",
        "authorizationheader",
        "applicationjson",
        "contentsecuritypolicy",
        "accesstokeninvalid",
        "sessionnotfounderror",
        "databaseconnectionexception",
        "unauthorizedaccessexception",
    }

    # Minimum unique character ratio for entropy candidate
    MIN_UNIQUE_CHAR_RATIO: float = 0.40

    # -------------------------------------------------------------
    # Severity Mappings
    # -------------------------------------------------------------
    ENTITY_SEVERITY: Dict[EntityType, Severity] = {
        # Secrets are Critical
        EntityType.PASSWORD: Severity.CRITICAL,
        EntityType.PRIVATE_KEY: Severity.CRITICAL,
        EntityType.API_KEY: Severity.CRITICAL,
        EntityType.BEARER_TOKEN: Severity.CRITICAL,
        EntityType.DB_CREDENTIAL: Severity.CRITICAL,
        EntityType.CLOUD_CREDENTIAL: Severity.CRITICAL,
        EntityType.HIGH_ENTROPY_SECRET: Severity.HIGH,  # High confidence heuristic

        # PII
        EntityType.ID_NUMBER: Severity.HIGH,
        EntityType.STREET_ADDRESS: Severity.HIGH,
        EntityType.PHONE: Severity.HIGH,
        EntityType.EMAIL: Severity.MEDIUM,
        EntityType.NAME: Severity.MEDIUM,
        EntityType.USERNAME: Severity.MEDIUM,
        EntityType.IP_ADDRESS: Severity.MEDIUM,
        EntityType.PERSONAL_URL: Severity.LOW,
    }

    # -------------------------------------------------------------
    # ML Contextual PII Model Configuration
    # -------------------------------------------------------------
    ML_MODEL_PATH: str = "models/pii_ner"
    ML_ENABLED: bool = True
    ML_CONFIDENCE_THRESHOLD: float = 0.50


class RedactorConfig:
    """Redaction settings and placeholder formats."""
    # Placeholder pattern to recognize existing tokens
    PLACEHOLDER_REGEX: Pattern = re.compile(r"\[([A-Z_]+_\d+)\]")

    # Template for placeholder generation
    PLACEHOLDER_TEMPLATE: str = "[{entity_type}_{index}]"
