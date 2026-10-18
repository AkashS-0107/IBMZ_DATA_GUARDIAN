"""Inference module for contextual PII detection using trained spaCy model.

Provides a clean interface returning DetectionFinding objects with verified character
offsets, normalized EntityTypes, configurable confidence thresholds, and safe error handling.
Does not log or expose raw PII text in logs or exceptions.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import spacy
from config import DetectorConfig
from models import DetectionFinding, EntityType, Severity

# Safe logger without printing sensitive payload
logger = logging.getLogger("ml_pii_detector")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)


class MLPIIDetector:
    """Contextual PII entity detector using a trained spaCy NER model."""

    # Normalization mapping to canonical EntityType
    LABEL_TAXONOMY_MAP: Dict[str, EntityType] = {
        "NAME": EntityType.NAME,
        "NAME_STUDENT": EntityType.NAME,
        "EMAIL": EntityType.EMAIL,
        "PHONE": EntityType.PHONE,
        "PHONE_NUM": EntityType.PHONE,
        "PERSONAL_URL": EntityType.PERSONAL_URL,
        "URL_PERSONAL": EntityType.PERSONAL_URL,
        "ID_NUMBER": EntityType.ID_NUMBER,
        "ID_NUM": EntityType.ID_NUMBER,
        "STREET_ADDRESS": EntityType.STREET_ADDRESS,
        "USERNAME": EntityType.USERNAME,
    }

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        confidence_threshold: float = 0.50,
        enabled: bool = True,
        config: Optional[DetectorConfig] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.confidence_threshold = (
            confidence_threshold
            if confidence_threshold is not None
            else getattr(self.config, "ML_CONFIDENCE_THRESHOLD", 0.50)
        )
        self.enabled = enabled and getattr(self.config, "ML_ENABLED", True)
        self.model_path = Path(model_path or getattr(self.config, "ML_MODEL_PATH", "models/pii_ner"))
        self._nlp: Optional[spacy.Language] = None
        self._load_attempted: bool = False
        self._is_available: bool = False

        if self.enabled:
            self._load_model()

    def _load_model(self) -> None:
        """Load trained spaCy model from disk safely."""
        self._load_attempted = True
        if not self.model_path.is_dir() or not (self.model_path / "config.cfg").is_file():
            logger.info(
                "ML model artifacts not found at %s. Operating in rules-only fallback mode.",
                self.model_path
            )
            self._is_available = False
            return

        try:
            self._nlp = spacy.load(self.model_path)
            self._is_available = True
            logger.info("Successfully loaded ML PII model from %s", self.model_path)
        except Exception as exc:
            # Audit safe warning without exposing file contents or environment
            logger.warning(
                "Failed to load ML PII model from %s (%s). Falling back to rules-only mode.",
                self.model_path, type(exc).__name__
            )
            self._nlp = None
            self._is_available = False

    def is_available(self) -> bool:
        """Return True if the trained ML model is loaded and ready for inference."""
        return self.enabled and self._is_available and self._nlp is not None

    def detect(self, text: str) -> List[DetectionFinding]:
        """Detect contextual PII entities in text using the trained ML model.

        Returns structured DetectionFinding instances matching the system detector interface.
        Guarantees:
        1. Character offsets [start, end) within len(text).
        2. Normalization into standard EntityType.
        3. Never breaks or throws unhandled exceptions during inference.
        """
        if not self.is_available():
            return []

        if not text or not isinstance(text, str) or not text.strip():
            return []

        try:
            doc = self._nlp(text)
        except Exception as exc:
            logger.warning(
                "Safe audit: ML inference failure encountered (%s). Returning empty predictions.",
                type(exc).__name__
            )
            return []

        findings: List[DetectionFinding] = []
        text_len = len(text)

        for ent in doc.ents:
            raw_label = ent.label_
            entity_type = self.LABEL_TAXONOMY_MAP.get(raw_label.upper())
            if entity_type is None:
                # Skip unrecognized entity labels
                continue

            start = ent.start_char
            end = ent.end_char

            # Validate character boundary invariants
            if not (0 <= start < end <= text_len):
                logger.warning(
                    "Safe audit: ML predicted out-of-bounds span [%d, %d) for text length %d. Discarded.",
                    start, end, text_len
                )
                continue

            # Assign confidence: default 0.85 for detected entities by NER component
            # Check if beam parse or custom score exists
            confidence = 0.85
            if hasattr(ent, "_") and hasattr(ent._, "confidence") and ent._.confidence is not None:
                confidence = float(ent._.confidence)

            if confidence < self.confidence_threshold:
                continue

            severity = self.config.ENTITY_SEVERITY.get(entity_type, Severity.MEDIUM)

            finding = DetectionFinding(
                entity_type=entity_type,
                start=start,
                end=end,
                severity=severity,
                rule_id=f"ml:spacy_ner:{raw_label.lower()}",
                confidence=round(confidence, 2),
                description=f"Detected contextual {entity_type.value} via trained ML NER pipeline",
                metadata={"model_source": str(self.model_path.name), "raw_label": raw_label},
            )
            findings.append(finding)

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run contextual PII inference using trained spaCy NER model"
    )
    parser.add_argument(
        "--model-dir", "-m", type=str, default="models/pii_ner",
        help="Path to trained spaCy model directory"
    )
    parser.add_argument(
        "--text", "-t", type=str, required=True,
        help="Input text string to scan for contextual PII"
    )
    parser.add_argument(
        "--threshold", type=float, default=0.50,
        help="Confidence acceptance threshold (default: 0.50)"
    )

    args = parser.parse_args()
    detector = MLPIIDetector(model_path=args.model_dir, confidence_threshold=args.threshold)
    if not detector.is_available():
        print(f"Error: Model not available at {args.model_dir}", file=sys.stderr)
        sys.exit(1)

    findings = detector.detect(args.text)
    print(f"Detected {len(findings)} ML contextual findings:")
    for f in findings:
        print(f"  - [{f.start:>2}, {f.end:>3}) {f.entity_type.value:<14} (conf: {f.confidence:.2f}) rule: {f.rule_id}")


if __name__ == "__main__":
    main()
