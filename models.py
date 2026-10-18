"""Data models for AI Data Leak Guardian.

Defines validated data structures for detection findings, risk assessments,
redaction results, dataset records, and evaluation metrics.
All offset conventions are 0-based, half-open intervals [start, end).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    """Standardized severity levels for findings and overall risk."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting severity (higher is more severe)."""
        ranks = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks[self]


class EntityType(str, Enum):
    """Supported entity categories for PII and secrets."""
    # PII
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    NAME = "NAME"
    IP_ADDRESS = "IP_ADDRESS"
    PERSONAL_URL = "PERSONAL_URL"
    ID_NUMBER = "ID_NUMBER"
    USERNAME = "USERNAME"
    STREET_ADDRESS = "STREET_ADDRESS"

    # Secrets and credentials
    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    DB_CREDENTIAL = "DB_CREDENTIAL"
    PRIVATE_KEY = "PRIVATE_KEY"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    HIGH_ENTROPY_SECRET = "HIGH_ENTROPY_SECRET"


class DetectionFinding(BaseModel):
    """Structured representation of a sensitive data match.

    Zero-based, half-open character offset convention: [start, end).
    Sensitive raw values are intentionally excluded from logs and repr.
    """
    entity_type: EntityType
    start: int = Field(ge=0, description="0-based start character offset (inclusive)")
    end: int = Field(gt=0, description="0-based end character offset (exclusive)")
    severity: Severity
    rule_id: str = Field(description="Identifier of rule or heuristic that triggered detection")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0, description="Detection confidence score")
    description: str = Field(description="Safe, non-sensitive description of the match")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata")

    @model_validator(mode="after")
    def validate_offsets(self) -> DetectionFinding:
        if self.end <= self.start:
            raise ValueError(
                f"Invalid offset interval [{self.start}, {self.end}): "
                f"end must be strictly greater than start."
            )
        return self

    @property
    def span_length(self) -> int:
        return self.end - self.start

    def overlaps_with(self, other: DetectionFinding) -> bool:
        """Return True if this finding overlaps with another finding."""
        return max(self.start, other.start) < min(self.end, other.end)

    def __repr__(self) -> str:
        """Safe representation excluding any raw text values."""
        return (
            f"DetectionFinding(type={self.entity_type.value}, span=[{self.start}, {self.end}), "
            f"severity={self.severity.value}, rule={self.rule_id}, conf={self.confidence:.2f})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class RiskAssessment(BaseModel):
    """Risk classification result with explainable audit trail."""
    risk_level: Severity
    reasons: List[str] = Field(default_factory=list, description="Audit explanations for risk assignment")
    findings_count: int = Field(ge=0)
    critical_count: int = Field(ge=0, default=0)
    high_count: int = Field(ge=0, default=0)
    medium_count: int = Field(ge=0, default=0)
    low_count: int = Field(ge=0, default=0)
    findings: List[DetectionFinding] = Field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"RiskAssessment(level={self.risk_level.value}, findings={self.findings_count}, "
            f"critical={self.critical_count}, high={self.high_count}, "
            f"medium={self.medium_count}, low={self.low_count})"
        )


class RedactionResult(BaseModel):
    """Result of reversible redaction operation."""
    session_id: str
    masked_text: str
    placeholders_count: int = Field(ge=0)
    unique_placeholders: int = Field(ge=0)
    findings_redacted: int = Field(ge=0)


class RestorationResult(BaseModel):
    """Result of reversible restoration operation with audit detail."""
    restored_text: str
    restored_placeholders: List[str] = Field(default_factory=list)
    unrestored_placeholders: List[str] = Field(default_factory=list)
    is_fully_restored: bool = True


class GroundTruthSpan(BaseModel):
    """Labelled span in benchmark datasets."""
    entity_type: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    label: Optional[str] = None

    @model_validator(mode="after")
    def validate_offsets(self) -> GroundTruthSpan:
        if self.end <= self.start:
            raise ValueError(f"Ground truth span end ({self.end}) must be > start ({self.start})")
        return self


class DatasetRecord(BaseModel):
    """Normalized document representation for benchmark evaluation."""
    document_id: str
    text: str
    ground_truth: List[GroundTruthSpan] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        # We allow empty strings, but ensure it's a string
        return v

    @model_validator(mode="after")
    def validate_span_bounds(self) -> DatasetRecord:
        text_len = len(self.text)
        for i, span in enumerate(self.ground_truth):
            if span.end > text_len:
                raise ValueError(
                    f"Ground truth span {i} [{span.start}, {span.end}) "
                    f"exceeds text length {text_len} in doc {self.document_id}"
                )
        return self


class EvaluationMetrics(BaseModel):
    """Precision, Recall, F1 and counts for an entity type or overall."""
    category: str
    true_positives: int = Field(ge=0, default=0)
    false_positives: int = Field(ge=0, default=0)
    false_negatives: int = Field(ge=0, default=0)
    precision: float = Field(ge=0.0, le=1.0, default=0.0)
    recall: float = Field(ge=0.0, le=1.0, default=0.0)
    f1_score: float = Field(ge=0.0, le=1.0, default=0.0)

    @classmethod
    def calculate(cls, category: str, tp: int, fp: int, fn: int) -> EvaluationMetrics:
        """Calculate metrics safely with zero-division protection."""
        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 and tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fn == 0 and tp == 0 and fp == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return cls(
            category=category,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
        )


class EvaluationReport(BaseModel):
    """Comprehensive evaluation report across records."""
    total_records: int
    matching_policy: str = "exact-span"
    overall_micro: EvaluationMetrics
    overall_macro_f1: float
    per_entity: Dict[str, EvaluationMetrics]
