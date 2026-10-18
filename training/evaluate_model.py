"""Independent and comparative evaluation pipeline for PII models.

Evaluates:
1. ML Model alone
2. Rule-based detector alone
3. Combined Hybrid detector

against identical held-out test documents. Computes exact-span Precision, Recall, F1,
and per-entity metrics without leaking sensitive text.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dataset_loader import load_synthetic_jsonl
from detector import Detector
from evaluation import Evaluator, format_evaluation_report
from models import DatasetRecord, EvaluationReport
from training.predict import MLPIIDetector

logger = logging.getLogger("evaluate_model")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)


def evaluate_comparative_pipeline(
    test_data_path: str | Path,
    model_dir: str | Path = "models/pii_ner",
    matching_policy: str = "exact-span",
    output_report_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Run comparative evaluation of ML alone, Rules alone, and Hybrid detector."""
    test_path = Path(test_data_path)
    model_path = Path(model_dir)

    if not test_path.is_file():
        raise FileNotFoundError(f"Held-out test records not found at: {test_path}")

    # Load test records
    records = load_synthetic_jsonl(test_path)
    if not records:
        raise ValueError(f"No valid records found in {test_path}")

    logger.info("Evaluating on %d held-out test records (Policy: %s)", len(records), matching_policy)

    # 1. ML Model Alone
    ml_detector = MLPIIDetector(model_path=model_path, enabled=True)
    ml_evaluator = Evaluator(detector=ml_detector, matching_policy=matching_policy)
    ml_report = ml_evaluator.evaluate_dataset(records)

    # 2. Rule-based Detector Alone (rules-only mode)
    rules_detector = Detector(ml_detector=MLPIIDetector(enabled=False))
    rules_evaluator = Evaluator(detector=rules_detector, matching_policy=matching_policy)
    rules_report = rules_evaluator.evaluate_dataset(records)

    # 3. Combined Hybrid Detector
    hybrid_detector = Detector(ml_detector=ml_detector)
    hybrid_evaluator = Evaluator(detector=hybrid_detector, matching_policy=matching_policy)
    hybrid_report = hybrid_evaluator.evaluate_dataset(records)

    # Format reports
    print("\n" + "=" * 76)
    print("MODE 1: ML MODEL ALONE")
    print("=" * 76)
    print(format_evaluation_report(ml_report))

    print("\n" + "=" * 76)
    print("MODE 2: RULE-BASED DETECTOR ALONE (RULES-ONLY MODE)")
    print("=" * 76)
    print(format_evaluation_report(rules_report))

    print("\n" + "=" * 76)
    print("MODE 3: COMBINED HYBRID DETECTOR (RULES + ML + ENTROPY)")
    print("=" * 76)
    print(format_evaluation_report(hybrid_report))

    # Consolidated output payload
    def _report_to_dict(rep: EvaluationReport) -> Dict[str, Any]:
        return {
            "total_records": rep.total_records,
            "matching_policy": rep.matching_policy,
            "overall_micro": rep.overall_micro.model_dump(),
            "overall_macro_f1": rep.overall_macro_f1,
            "per_entity": {k: v.model_dump() for k, v in rep.per_entity.items()},
        }

    summary = {
        "test_dataset": str(test_path),
        "total_test_records": len(records),
        "matching_policy": matching_policy,
        "ml_model_dir": str(model_path),
        "ml_model_available": ml_detector.is_available(),
        "ml_alone": _report_to_dict(ml_report),
        "rules_alone": _report_to_dict(rules_report),
        "hybrid": _report_to_dict(hybrid_report),
    }

    if output_report_path:
        out_p = Path(output_report_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with out_p.open("w", encoding="utf-8") as rf:
            json.dump(summary, rf, indent=2)
        logger.info("Saved comparative evaluation report to %s", out_p)

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate ML alone, Rules alone, and Hybrid detector on held-out test data"
    )
    parser.add_argument(
        "--test-data", "-t", type=str, default="datasets/processed/test_records.jsonl",
        help="Path to held-out test records JSONL"
    )
    parser.add_argument(
        "--model-dir", "-m", type=str, default="models/pii_ner",
        help="Path to trained spaCy model directory"
    )
    parser.add_argument(
        "--policy", "-p", type=str, default="exact-span", choices=["exact-span", "overlap"],
        help="Span matching policy (default: exact-span)"
    )
    parser.add_argument(
        "--output-report", "-o", type=str, default="models/pii_ner/evaluation_report.json",
        help="Destination path for evaluation results JSON"
    )

    args = parser.parse_args()
    evaluate_comparative_pipeline(
        test_data_path=args.test_data,
        model_dir=args.model_dir,
        matching_policy=args.policy,
        output_report_path=args.output_report,
    )


if __name__ == "__main__":
    main()
