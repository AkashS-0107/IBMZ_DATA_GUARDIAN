"""Evaluation pipeline and benchmark scoring for AI Data Leak Guardian.

Compares detector findings against ground-truth annotations to calculate
True Positives, False Positives, False Negatives, Precision, Recall, and F1.
Supports exact-span matching by default, per-entity breakdowns, and safe reporting.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from detector import Detector
from models import DatasetRecord, DetectionFinding, EvaluationMetrics, EvaluationReport, GroundTruthSpan


class Evaluator:
    """Evaluates detector performance against annotated datasets."""

    VALID_POLICIES = {"exact-span", "overlap"}

    def __init__(
        self,
        detector: Optional[Detector] = None,
        matching_policy: str = "exact-span"
    ) -> None:
        if matching_policy not in self.VALID_POLICIES:
            raise ValueError(
                f"Unknown matching policy '{matching_policy}'. Supported policies: {sorted(self.VALID_POLICIES)}"
            )
        self.detector = detector or Detector()
        self.matching_policy = matching_policy

    def _spans_match(
        self,
        pred: DetectionFinding,
        gt: GroundTruthSpan
    ) -> bool:
        """Check if predicted finding matches ground truth span according to policy."""
        pred_type = pred.entity_type.value if hasattr(pred.entity_type, "value") else str(pred.entity_type)
        gt_type = gt.entity_type.upper()

        # Entity type compatibility
        if pred_type != gt_type:
            return False

        if self.matching_policy == "exact-span":
            return pred.start == gt.start and pred.end == gt.end
        elif self.matching_policy == "overlap":
            # Any non-zero intersection
            return max(pred.start, gt.start) < min(pred.end, gt.end)
        else:
            raise ValueError(f"Unknown matching policy: {self.matching_policy}")

    def evaluate_record(
        self,
        record: DatasetRecord
    ) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
        """Evaluate a single record and return (tp_counts, fp_counts, fn_counts) per entity type."""
        predictions = self.detector.detect(record.text)
        gt_spans = record.ground_truth

        tp_counts: Dict[str, int] = {}
        fp_counts: Dict[str, int] = {}
        fn_counts: Dict[str, int] = {}

        unmatched_gt: Set[int] = set(range(len(gt_spans)))
        unmatched_pred: Set[int] = set(range(len(predictions)))

        # Match predictions to ground truth spans 1-to-1
        for p_idx, pred in enumerate(predictions):
            matched_gt_idx = None
            for g_idx in unmatched_gt:
                if self._spans_match(pred, gt_spans[g_idx]):
                    matched_gt_idx = g_idx
                    break

            if matched_gt_idx is not None:
                entity = pred.entity_type.value if hasattr(pred.entity_type, "value") else str(pred.entity_type)
                tp_counts[entity] = tp_counts.get(entity, 0) + 1
                unmatched_gt.remove(matched_gt_idx)
                unmatched_pred.remove(p_idx)

        # Remaining unmatched predictions are False Positives
        for p_idx in unmatched_pred:
            pred = predictions[p_idx]
            entity = pred.entity_type.value if hasattr(pred.entity_type, "value") else str(pred.entity_type)
            fp_counts[entity] = fp_counts.get(entity, 0) + 1

        # Remaining unmatched ground truth spans are False Negatives
        for g_idx in unmatched_gt:
            gt = gt_spans[g_idx]
            entity = gt.entity_type.upper()
            fn_counts[entity] = fn_counts.get(entity, 0) + 1

        return tp_counts, fp_counts, fn_counts

    def evaluate_dataset(self, records: List[DatasetRecord]) -> EvaluationReport:
        """Run complete evaluation across a list of dataset records."""
        total_tp: Dict[str, int] = {}
        total_fp: Dict[str, int] = {}
        total_fn: Dict[str, int] = {}
        all_categories: Set[str] = set()

        for record in records:
            tp, fp, fn = self.evaluate_record(record)
            for cat, count in tp.items():
                total_tp[cat] = total_tp.get(cat, 0) + count
                all_categories.add(cat)
            for cat, count in fp.items():
                total_fp[cat] = total_fp.get(cat, 0) + count
                all_categories.add(cat)
            for cat, count in fn.items():
                total_fn[cat] = total_fn.get(cat, 0) + count
                all_categories.add(cat)

        # Also register categories from ground truth in records
        for rec in records:
            for gt in rec.ground_truth:
                all_categories.add(gt.entity_type.upper())

        per_entity: Dict[str, EvaluationMetrics] = {}
        micro_tp = sum(total_tp.values())
        micro_fp = sum(total_fp.values())
        micro_fn = sum(total_fn.values())

        for cat in sorted(all_categories):
            tp = total_tp.get(cat, 0)
            fp = total_fp.get(cat, 0)
            fn = total_fn.get(cat, 0)
            per_entity[cat] = EvaluationMetrics.calculate(
                category=cat, tp=tp, fp=fp, fn=fn
            )

        overall_micro = EvaluationMetrics.calculate(
            category="OVERALL_MICRO",
            tp=micro_tp,
            fp=micro_fp,
            fn=micro_fn,
        )

        macro_f1 = (
            sum(m.f1_score for m in per_entity.values()) / len(per_entity)
            if per_entity else 0.0
        )

        return EvaluationReport(
            total_records=len(records),
            matching_policy=self.matching_policy,
            overall_micro=overall_micro,
            overall_macro_f1=round(macro_f1, 4),
            per_entity=per_entity,
        )


def format_evaluation_report(report: EvaluationReport) -> str:
    """Format evaluation metrics into an audit-safe ASCII table."""
    lines: List[str] = []
    lines.append("=" * 74)
    lines.append(f"AI DATA LEAK GUARDIAN - EVALUATION REPORT")
    lines.append(f"Total Records: {report.total_records} | Matching Policy: {report.matching_policy}")
    lines.append("-" * 74)
    lines.append(
        f"{'Entity Type':<22} | {'TP':>4} | {'FP':>4} | {'FN':>4} | {'Precision':>9} | {'Recall':>7} | {'F1':>6}"
    )
    lines.append("-" * 74)

    for cat, m in sorted(report.per_entity.items()):
        lines.append(
            f"{cat:<22} | {m.true_positives:>4} | {m.false_positives:>4} | {m.false_negatives:>4} | "
            f"{m.precision:>9.4f} | {m.recall:>7.4f} | {m.f1_score:>6.4f}"
        )

    lines.append("-" * 74)
    om = report.overall_micro
    lines.append(
        f"{'OVERALL (MICRO)':<22} | {om.true_positives:>4} | {om.false_positives:>4} | {om.false_negatives:>4} | "
        f"{om.precision:>9.4f} | {om.recall:>7.4f} | {om.f1_score:>6.4f}"
    )
    lines.append(f"OVERALL MACRO F1: {report.overall_macro_f1:.4f}")
    lines.append("=" * 74)
    return "\n".join(lines)
