"""Risk assessment engine for AI Data Leak Guardian.

Evaluates structured detection findings against deterministic rules to classify
exposure risk into exactly four levels: Low, Medium, High, or Critical.
Includes safe, explainable audit rationales for every assessment.
"""

from __future__ import annotations

from typing import List
from detector import resolve_overlaps
from models import DetectionFinding, RiskAssessment, Severity


def assess_risk(findings: List[DetectionFinding]) -> RiskAssessment:
    """Assess overall exposure risk from a list of detection findings.

    Deterministic classification policy:
    - CRITICAL: Any confirmed credential, password, private key, cloud token,
      or database connection string (Severity.CRITICAL).
    - HIGH: Direct identity markers (SSN/government ID), phone numbers,
      high-entropy candidate secrets, or >= 2 Medium PII findings (aggregated risk).
    - MEDIUM: Exactly 1 isolated Medium-severity PII finding (e.g. 1 email or 1 IP).
    - LOW: No sensitive findings, or only low-severity items (e.g. public URLs).

    Secret detection always takes priority over PII findings.
    """
    clean_findings = resolve_overlaps(findings) if findings else []
    total = len(clean_findings)
    critical_count = sum(1 for f in clean_findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in clean_findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in clean_findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in clean_findings if f.severity == Severity.LOW)

    reasons: List[str] = []

    # Priority 1: Critical Secrets
    if critical_count > 0:
        overall_level = Severity.CRITICAL
        reasons.append(
            f"CRITICAL: Detected {critical_count} confirmed credential or secret finding(s) "
            f"(e.g., private keys, passwords, bearer tokens, or cloud access keys). "
            f"Transmission to external AI models would cause immediate credential exposure."
        )
        if high_count > 0 or medium_count > 0:
            reasons.append(
                f"Secondary findings present: {high_count} High-severity and {medium_count} Medium-severity item(s)."
            )

    # Priority 2: High Severity (Identity numbers, phone numbers, high-entropy secrets)
    elif high_count > 0:
        overall_level = Severity.HIGH
        reasons.append(
            f"HIGH: Detected {high_count} high-consequence finding(s) "
            f"(such as telephone numbers, identity numbers, or high-entropy candidate secrets). "
            f"Presents direct privacy risk or potential secret exposure."
        )
        if medium_count > 0:
            reasons.append(f"Additional context: {medium_count} Medium-severity PII finding(s) also detected.")

    # Priority 3: Multiple Medium PII findings (Aggregated re-identification risk)
    elif medium_count >= 2:
        overall_level = Severity.HIGH
        reasons.append(
            f"HIGH: Multiple ({medium_count}) Medium-severity PII findings detected. "
            f"Combining multiple identifiers significantly increases person re-identification risk."
        )

    # Priority 4: Isolated single Medium PII
    elif medium_count == 1:
        overall_level = Severity.MEDIUM
        reasons.append(
            "MEDIUM: Exactly one isolated personal identifier detected "
            "(e.g., an email address or IP address). Limited exposure risk."
        )

    # Priority 5: Low severity only
    elif low_count > 0:
        overall_level = Severity.LOW
        reasons.append(
            f"LOW: Only {low_count} low-risk contextual item(s) detected "
            f"(e.g., public profile links). No credentials or direct high-risk PII found."
        )

    # Priority 6: Clean text
    else:
        overall_level = Severity.LOW
        reasons.append("LOW: No sensitive personal information, credentials, or secrets detected.")

    return RiskAssessment(
        risk_level=overall_level,
        reasons=reasons,
        findings_count=total,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        findings=clean_findings,
    )
