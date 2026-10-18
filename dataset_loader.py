"""Dataset loader and adapter module for AI Data Leak Guardian.

Supports loading and normalizing benchmark datasets:
1. Synthetic JSONL fixtures (fixtures/synthetic_pii.jsonl, fixtures/synthetic_secrets.jsonl).
2. The Kaggle 'pii-detection-removal-from-educational-data' competition dataset (train.json).
3. Generic JSON, JSONL, and CSV ground-truth datasets.

All loaders validate character offsets and ensure zero sensitive data is exposed in exceptions.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

from models import DatasetRecord, GroundTruthSpan


# Mapping from Kaggle competition BIO labels to internal standardized EntityType names
KAGGLE_LABEL_MAP: Dict[str, str] = {
    "NAME_STUDENT": "NAME",
    "EMAIL": "EMAIL",
    "PHONE_NUM": "PHONE",
    "URL_PERSONAL": "PERSONAL_URL",
    "ID_NUM": "ID_NUMBER",
    "STREET_ADDRESS": "STREET_ADDRESS",
    "USERNAME": "USERNAME",
}


def load_synthetic_jsonl(
    file_path: str | Path,
    sample_size: Optional[int] = None
) -> List[DatasetRecord]:
    """Load normalized DatasetRecord entries from a JSONL file.

    Expected JSON line schema:
    {
        "document_id": "doc_1",
        "text": "My email is test@example.com",
        "spans": [{"entity_type": "EMAIL", "start": 12, "end": 28, "label": "EMAIL"}],
        "metadata": {}  (optional)
    }
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found at: {path}")

    records: List[DatasetRecord] = []
    seen_ids: Set[str] = set()

    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON on line {line_num} in {path.name}: {exc.msg}")

            doc_id = str(data.get("document_id") or data.get("id") or f"doc_{line_num}")
            if doc_id in seen_ids:
                # Deduplicate by document ID
                continue
            seen_ids.add(doc_id)

            text = data.get("text")
            if text is None:
                raise ValueError(f"Missing required 'text' field on line {line_num} in {path.name}")

            raw_spans = data.get("spans") or data.get("ground_truth") or []
            ground_truth: List[GroundTruthSpan] = []
            seen_spans: Set[Tuple[str, int, int]] = set()

            for s_idx, span_data in enumerate(raw_spans):
                if not isinstance(span_data, dict):
                    raise ValueError(f"Malformed span #{s_idx} on line {line_num}: expected dict")
                try:
                    gt_span = GroundTruthSpan(
                        entity_type=str(span_data["entity_type"]).upper(),
                        start=int(span_data["start"]),
                        end=int(span_data["end"]),
                        label=span_data.get("label"),
                    )
                    span_key = (gt_span.entity_type, gt_span.start, gt_span.end)
                    if span_key not in seen_spans:
                        seen_spans.add(span_key)
                        ground_truth.append(gt_span)
                except (KeyError, ValueError, TypeError) as exc:
                    raise ValueError(
                        f"Invalid span #{s_idx} on line {line_num} in doc {doc_id}: {exc}"
                    )

            record = DatasetRecord(
                document_id=doc_id,
                text=text,
                ground_truth=ground_truth,
                metadata=data.get("metadata", {}),
            )
            records.append(record)

            if sample_size and len(records) >= sample_size:
                break

    return records


def load_kaggle_pii_json(
    file_path: str | Path,
    sample_size: Optional[int] = None
) -> List[DatasetRecord]:
    """Adapter for Kaggle 'The Learning Agency Lab - PII Data Detection' competition dataset.

    Parses competition train.json format:
    [
        {
            "document": 1234,
            "full_text": "...",
            "tokens": ["word1", "word2", ...],
            "trailing_whitespace": [true, false, ...],
            "labels": ["O", "B-NAME_STUDENT", "I-NAME_STUDENT", ...]
        }, ...
    ]
    Converts BIO token labels to character-level ground truth spans.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Kaggle dataset file not found at: {path}")

    with path.open("r", encoding="utf-8") as f:
        try:
            raw_data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse Kaggle JSON file {path.name}: {exc.msg}")

    if not isinstance(raw_data, list):
        raise ValueError(f"Kaggle competition format expected list of documents, got {type(raw_data).__name__}")

    records: List[DatasetRecord] = []
    seen_ids: Set[str] = set()

    for doc_idx, doc_item in enumerate(raw_data):
        if sample_size and len(records) >= sample_size:
            break

        if not isinstance(doc_item, dict):
            raise ValueError(f"Document entry #{doc_idx} is not a valid JSON object")

        for req_field in ("document", "full_text", "tokens", "trailing_whitespace", "labels"):
            if req_field not in doc_item:
                raise ValueError(f"Document #{doc_idx} is missing required Kaggle field: '{req_field}'")

        doc_id = str(doc_item["document"])
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)

        full_text = doc_item["full_text"]
        tokens = doc_item["tokens"]
        trailing_ws = doc_item["trailing_whitespace"]
        labels = doc_item["labels"]

        if not (len(tokens) == len(trailing_ws) == len(labels)):
            raise ValueError(
                f"Token length mismatch in doc {doc_id}: tokens={len(tokens)}, "
                f"whitespace={len(trailing_ws)}, labels={len(labels)}"
            )

        # Reconstruct token character offsets in full_text
        token_spans: List[Tuple[int, int]] = []
        cursor = 0
        for token in tokens:
            # Locate token starting from cursor
            idx = full_text.find(token, cursor)
            if idx == -1:
                # Fallback: token not found exactly, approximate cursor
                idx = cursor
            start_off = idx
            end_off = idx + len(token)
            token_spans.append((start_off, end_off))
            cursor = end_off

        # Convert BIO labels to Character Spans
        ground_truth: List[GroundTruthSpan] = []
        seen_spans: Set[Tuple[str, int, int]] = set()
        current_span_start: Optional[int] = None
        current_span_end: Optional[int] = None
        current_entity_type: Optional[str] = None
        current_raw_label: Optional[str] = None

        def _add_span(etype: str, s: int, e: int, lbl: Optional[str]) -> None:
            key = (etype, s, e)
            if key not in seen_spans:
                seen_spans.add(key)
                ground_truth.append(
                    GroundTruthSpan(
                        entity_type=etype,
                        start=s,
                        end=e,
                        label=lbl,
                    )
                )

        for t_idx, label in enumerate(labels):
            if label.startswith("B-"):
                # Complete previous span if open
                if current_entity_type and current_span_start is not None and current_span_end is not None:
                    _add_span(current_entity_type, current_span_start, current_span_end, current_raw_label)
                raw_tag = label[2:]
                current_entity_type = KAGGLE_LABEL_MAP.get(raw_tag, raw_tag)
                current_raw_label = label
                current_span_start = token_spans[t_idx][0]
                current_span_end = token_spans[t_idx][1]

            elif label.startswith("I-"):
                raw_tag = label[2:]
                mapped = KAGGLE_LABEL_MAP.get(raw_tag, raw_tag)
                if current_entity_type == mapped and current_span_start is not None:
                    # Extend current span
                    current_span_end = token_spans[t_idx][1]
                else:
                    # Unexpected I- tag without matching B-, start new span
                    if current_entity_type and current_span_start is not None and current_span_end is not None:
                        _add_span(current_entity_type, current_span_start, current_span_end, current_raw_label)
                    current_entity_type = mapped
                    current_raw_label = label
                    current_span_start = token_spans[t_idx][0]
                    current_span_end = token_spans[t_idx][1]

            else:  # "O" or other non-PII label
                if current_entity_type and current_span_start is not None and current_span_end is not None:
                    _add_span(current_entity_type, current_span_start, current_span_end, current_raw_label)
                    current_entity_type = None
                    current_span_start = None
                    current_span_end = None
                    current_raw_label = None

        # Add trailing open span if any
        if current_entity_type and current_span_start is not None and current_span_end is not None:
            _add_span(current_entity_type, current_span_start, current_span_end, current_raw_label)

        record = DatasetRecord(
            document_id=doc_id,
            text=full_text,
            ground_truth=ground_truth,
            metadata={"source": "kaggle_pii_detection"},
        )
        records.append(record)

    return records


def load_csv_dataset(
    file_path: str | Path,
    sample_size: Optional[int] = None
) -> List[DatasetRecord]:
    """Load dataset from CSV format with columns: document_id, text, spans_json."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found at: {path}")

    records: List[DatasetRecord] = []
    seen_ids: Set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "text" not in reader.fieldnames:
            raise ValueError(f"CSV {path.name} must contain at least 'text' column")

        for row_idx, row in enumerate(reader, start=1):
            doc_id = row.get("document_id") or str(row_idx)
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)

            text = row.get("text")
            if text is None:
                raise ValueError(f"Missing required 'text' column in CSV row {row_idx} in {path.name}")

            spans_str = row.get("spans_json") or row.get("spans") or "[]"
            try:
                spans_data = json.loads(spans_str)
            except json.JSONDecodeError:
                raise ValueError(f"Malformed spans_json in CSV row {row_idx}")

            seen_spans: Set[Tuple[str, int, int]] = set()
            ground_truth: List[GroundTruthSpan] = []
            for s in spans_data:
                gt = GroundTruthSpan(
                    entity_type=str(s["entity_type"]).upper(),
                    start=int(s["start"]),
                    end=int(s["end"]),
                    label=s.get("label"),
                )
                span_key = (gt.entity_type, gt.start, gt.end)
                if span_key not in seen_spans:
                    seen_spans.add(span_key)
                    ground_truth.append(gt)

            record = DatasetRecord(
                document_id=doc_id,
                text=text,
                ground_truth=ground_truth,
            )
            records.append(record)

            if sample_size and len(records) >= sample_size:
                break

    return records
