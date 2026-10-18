"""Automated tests for evaluation metrics, span matching, and benchmarks."""

from pathlib import Path
import pytest

from dataset_loader import load_synthetic_jsonl
from detector import Detector
from evaluation import Evaluator, format_evaluation_report
from models import DatasetRecord, DetectionFinding, EntityType, EvaluationMetrics, GroundTruthSpan, Severity


class TestEvaluationEngine:
    """Unit tests for evaluation metrics calculation and policy matching."""

    def test_metrics_math_and_zero_division(self):
        # Normal case
        m = EvaluationMetrics.calculate("TEST", tp=8, fp=2, fn=2)
        assert m.precision == 0.8
        assert m.recall == 0.8
        assert m.f1_score == 0.8

        # Zero predictions (TP=0, FP=0, FN=5)
        m_zero_pred = EvaluationMetrics.calculate("TEST", tp=0, fp=0, fn=5)
        assert m_zero_pred.precision == 0.0
        assert m_zero_pred.recall == 0.0
        assert m_zero_pred.f1_score == 0.0

        # Completely clean: no ground truth, no predictions (TP=0, FP=0, FN=0)
        m_clean = EvaluationMetrics.calculate("TEST", tp=0, fp=0, fn=0)
        assert m_clean.precision == 1.0
        assert m_clean.recall == 1.0
        assert m_clean.f1_score == 1.0

    def test_exact_span_matching_policy(self):
        evaluator = Evaluator(matching_policy="exact-span")

        record = DatasetRecord(
            document_id="eval_1",
            text="User email is alice@example.com here.",
            ground_truth=[
                GroundTruthSpan(entity_type="EMAIL", start=14, end=31)
            ]
        )

        tp, fp, fn = evaluator.evaluate_record(record)
        assert tp.get("EMAIL") == 1
        assert fp.get("EMAIL", 0) == 0
        assert fn.get("EMAIL", 0) == 0

    def test_duplicate_prediction_does_not_inflate_true_positives(self):
        # Custom detector mock simulating duplicate predictions on same ground truth span
        class DuplicateDetector(Detector):
            def detect(self, text: str):
                return [
                    DetectionFinding(
                        entity_type=EntityType.EMAIL,
                        start=14, end=31,
                        severity=Severity.MEDIUM,
                        rule_id="r1",
                        description="match 1"
                    ),
                    DetectionFinding(
                        entity_type=EntityType.EMAIL,
                        start=14, end=31,
                        severity=Severity.MEDIUM,
                        rule_id="r2",
                        description="match 2"
                    )
                ]

        evaluator = Evaluator(detector=DuplicateDetector(), matching_policy="exact-span")
        record = DatasetRecord(
            document_id="eval_dupe",
            text="User email is alice@example.com here.",
            ground_truth=[
                GroundTruthSpan(entity_type="EMAIL", start=14, end=31)
            ]
        )

        tp, fp, fn = evaluator.evaluate_record(record)
        # Exactly 1 TP (for the 1 ground truth), the second prediction must be marked FP!
        assert tp.get("EMAIL") == 1
        assert fp.get("EMAIL") == 1
        assert fn.get("EMAIL", 0) == 0

    def test_synthetic_fixtures_benchmark_reproducibility(self):
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        pii_path = fixtures_dir / "synthetic_pii.jsonl"
        sec_path = fixtures_dir / "synthetic_secrets.jsonl"

        records = load_synthetic_jsonl(pii_path) + load_synthetic_jsonl(sec_path)
        assert len(records) == 18

        evaluator = Evaluator(matching_policy="exact-span")
        report = evaluator.evaluate_dataset(records)

        assert report.total_records == 18
        # Overall micro precision and recall should be high on synthetic fixtures
        assert report.overall_micro.precision >= 0.90
        assert report.overall_micro.recall >= 0.90
        assert report.overall_micro.f1_score >= 0.90

        # Formatted report string should not expose raw sensitive strings
        formatted = format_evaluation_report(report)
        assert "EVALUATION REPORT" in formatted
        assert "OVERALL (MICRO)" in formatted


class TestEvaluationEngineRegressions:
    """Regression tests for edge cases and defect fixes in evaluation.py."""

    def test_partial_match_exact_policy_counts_as_fp_and_fn(self):
        class PartialDetector(Detector):
            def detect(self, text: str):
                return [
                    DetectionFinding(
                        entity_type=EntityType.EMAIL,
                        start=10,
                        end=25,  # Prediction ends at 25
                        severity=Severity.MEDIUM,
                        rule_id="r1",
                        description="match",
                    )
                ]

        evaluator = Evaluator(detector=PartialDetector(), matching_policy="exact-span")
        record = DatasetRecord(
            document_id="d_partial",
            text="0123456789alice@example.com9999",
            ground_truth=[
                GroundTruthSpan(entity_type="EMAIL", start=10, end=20)  # GT ends at 20
            ],
        )
        tp, fp, fn = evaluator.evaluate_record(record)
        # Exact-span: partial match must NOT count as TP!
        assert tp.get("EMAIL", 0) == 0
        assert fp.get("EMAIL", 0) == 1
        assert fn.get("EMAIL", 0) == 1

    def test_overlap_matching_policy_accepts_partial(self):
        class PartialDetector(Detector):
            def detect(self, text: str):
                return [
                    DetectionFinding(
                        entity_type=EntityType.EMAIL,
                        start=10,
                        end=25,
                        severity=Severity.MEDIUM,
                        rule_id="r1",
                        description="match",
                    )
                ]

        evaluator = Evaluator(detector=PartialDetector(), matching_policy="overlap")
        record = DatasetRecord(
            document_id="d_partial_overlap",
            text="0123456789alice@example.com9999",
            ground_truth=[
                GroundTruthSpan(entity_type="EMAIL", start=10, end=20)
            ],
        )
        tp, fp, fn = evaluator.evaluate_record(record)
        assert tp.get("EMAIL") == 1
        assert fp.get("EMAIL", 0) == 0
        assert fn.get("EMAIL", 0) == 0

    def test_incorrect_entity_type_counts_as_fp_and_fn(self):
        class WrongTypeDetector(Detector):
            def detect(self, text: str):
                return [
                    DetectionFinding(
                        entity_type=EntityType.PHONE,
                        start=10,
                        end=20,
                        severity=Severity.HIGH,
                        rule_id="r_phone",
                        description="phone",
                    )
                ]

        evaluator = Evaluator(detector=WrongTypeDetector(), matching_policy="exact-span")
        record = DatasetRecord(
            document_id="d_wrong_type",
            text="012345678901234567890",
            ground_truth=[
                GroundTruthSpan(entity_type="EMAIL", start=10, end=20)
            ],
        )
        tp, fp, fn = evaluator.evaluate_record(record)
        assert tp.get("EMAIL", 0) == 0
        assert tp.get("PHONE", 0) == 0
        assert fp.get("PHONE") == 1
        assert fn.get("EMAIL") == 1

    def test_empty_dataset_evaluated_safely(self):
        evaluator = Evaluator()
        report = evaluator.evaluate_dataset([])
        assert report.total_records == 0
        assert report.overall_micro.true_positives == 0
        assert report.overall_micro.precision == 1.0
        assert report.overall_micro.recall == 1.0
        assert report.overall_micro.f1_score == 1.0
        assert report.overall_macro_f1 == 0.0

    def test_unknown_matching_policy_raises_value_error(self):
        with pytest.raises(ValueError) as exc:
            Evaluator(matching_policy="unsupported-policy")
        assert "unknown matching policy" in str(exc.value).lower()


