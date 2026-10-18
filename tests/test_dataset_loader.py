"""Automated tests for dataset loading, normalization, and validation."""

import json
from pathlib import Path
import pytest

from dataset_loader import load_csv_dataset, load_kaggle_pii_json, load_synthetic_jsonl
from models import DatasetRecord


class TestDatasetLoader:
    """Tests for dataset loading utilities and error validation."""

    def test_load_valid_synthetic_jsonl(self, tmp_path: Path):
        file_path = tmp_path / "valid.jsonl"
        records_data = [
            {
                "document_id": "doc_1",
                "text": "Hello user@example.com here.",
                "spans": [{"entity_type": "EMAIL", "start": 6, "end": 22, "label": "EMAIL"}]
            },
            {
                "document_id": "doc_2",
                "text": "Clean text without findings.",
                "spans": []
            }
        ]
        with file_path.open("w", encoding="utf-8") as f:
            for r in records_data:
                f.write(json.dumps(r) + "\n")

        records = load_synthetic_jsonl(file_path)
        assert len(records) == 2
        assert records[0].document_id == "doc_1"
        assert len(records[0].ground_truth) == 1
        assert records[0].ground_truth[0].entity_type == "EMAIL"
        assert records[0].ground_truth[0].start == 6
        assert records[0].ground_truth[0].end == 22

    def test_sample_size_limiting(self, tmp_path: Path):
        file_path = tmp_path / "multi.jsonl"
        with file_path.open("w", encoding="utf-8") as f:
            for i in range(10):
                f.write(json.dumps({"document_id": f"d_{i}", "text": "Sample text", "spans": []}) + "\n")

        records = load_synthetic_jsonl(file_path, sample_size=3)
        assert len(records) == 3

    def test_deduplication_by_id(self, tmp_path: Path):
        file_path = tmp_path / "dupes.jsonl"
        with file_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"document_id": "dup_1", "text": "First instance", "spans": []}) + "\n")
            f.write(json.dumps({"document_id": "dup_1", "text": "Second duplicate", "spans": []}) + "\n")

        records = load_synthetic_jsonl(file_path)
        assert len(records) == 1
        assert records[0].text == "First instance"

    def test_missing_file_raises_safe_error(self):
        with pytest.raises(FileNotFoundError) as exc_info:
            load_synthetic_jsonl("non_existent_dataset_file.jsonl")
        assert "not found" in str(exc_info.value).lower()

    def test_missing_required_column_raises_error(self, tmp_path: Path):
        file_path = tmp_path / "missing_text.jsonl"
        with file_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"document_id": "d_1"}) + "\n")  # Missing 'text'

        with pytest.raises(ValueError) as exc_info:
            load_synthetic_jsonl(file_path)
        assert "missing required 'text' field" in str(exc_info.value).lower()

    def test_invalid_offset_bounds_rejected(self, tmp_path: Path):
        file_path = tmp_path / "bad_offsets.jsonl"
        # Offset end (99) exceeds text length (12)
        with file_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({
                "document_id": "d_bad",
                "text": "Short string",
                "spans": [{"entity_type": "EMAIL", "start": 0, "end": 99}]
            }) + "\n")

        with pytest.raises(ValueError) as exc_info:
            load_synthetic_jsonl(file_path)
        assert "exceeds text length" in str(exc_info.value).lower()

    def test_kaggle_competition_adapter(self, tmp_path: Path):
        kaggle_file = tmp_path / "train.json"
        kaggle_data = [
            {
                "document": 1001,
                "full_text": "Student Bob Smith submitted homework.",
                "tokens": ["Student", "Bob", "Smith", "submitted", "homework", "."],
                "trailing_whitespace": [True, True, True, True, False, False],
                "labels": ["O", "B-NAME_STUDENT", "I-NAME_STUDENT", "O", "O", "O"]
            }
        ]
        with kaggle_file.open("w", encoding="utf-8") as f:
            json.dump(kaggle_data, f)

        records = load_kaggle_pii_json(kaggle_file)
        assert len(records) == 1
        rec = records[0]
        assert rec.document_id == "1001"
        assert len(rec.ground_truth) == 1
        gt = rec.ground_truth[0]
        assert gt.entity_type == "NAME"
        assert rec.text[gt.start:gt.end] == "Bob Smith"

    def test_csv_dataset_loader(self, tmp_path: Path):
        csv_file = tmp_path / "data.csv"
        csv_content = (
            "document_id,text,spans_json\n"
            "c_1,Contact at contact@example.com,\"[{\"\"entity_type\"\": \"\"EMAIL\"\", \"\"start\"\": 11, \"\"end\"\": 30}]\"\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8")

        records = load_csv_dataset(csv_file)
        assert len(records) == 1
        assert records[0].document_id == "c_1"
        assert records[0].ground_truth[0].entity_type == "EMAIL"
        assert records[0].text[11:30] == "contact@example.com"


class TestDatasetLoaderRegressions:
    """Regression tests for edge cases and defect fixes in dataset_loader.py."""

    def test_duplicate_annotations_deduplicated_in_jsonl(self, tmp_path: Path):
        file_path = tmp_path / "dupe_spans.jsonl"
        # Two identical annotation spans for the same email
        record_data = {
            "document_id": "doc_dupe_spans",
            "text": "Send mail to user@example.com immediately.",
            "spans": [
                {"entity_type": "EMAIL", "start": 13, "end": 29},
                {"entity_type": "EMAIL", "start": 13, "end": 29},
            ],
        }
        with file_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(record_data) + "\n")

        records = load_synthetic_jsonl(file_path)
        assert len(records) == 1
        # Ground truth must be deduplicated to exactly 1 span
        assert len(records[0].ground_truth) == 1
        assert records[0].ground_truth[0].entity_type == "EMAIL"

    def test_duplicate_annotations_deduplicated_in_csv(self, tmp_path: Path):
        csv_file = tmp_path / "dupe_spans.csv"
        csv_content = (
            "document_id,text,spans_json\n"
            "c_dupe,Contact user@example.com,\""
            "[{\"\"entity_type\"\": \"\"EMAIL\"\", \"\"start\"\": 8, \"\"end\"\": 24},"
            "{\"\"entity_type\"\": \"\"EMAIL\"\", \"\"start\"\": 8, \"\"end\"\": 24}]\"\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8")

        records = load_csv_dataset(csv_file)
        assert len(records) == 1
        assert len(records[0].ground_truth) == 1

    def test_duplicate_documents_deduplicated_in_kaggle_loader(self, tmp_path: Path):
        kaggle_file = tmp_path / "dupe_docs.json"
        kaggle_data = [
            {
                "document": 2001,
                "full_text": "First instance of document 2001.",
                "tokens": ["First", "instance"],
                "trailing_whitespace": [True, False],
                "labels": ["O", "O"],
            },
            {
                "document": 2001,
                "full_text": "Duplicate instance of document 2001.",
                "tokens": ["Duplicate", "instance"],
                "trailing_whitespace": [True, False],
                "labels": ["O", "O"],
            },
        ]
        with kaggle_file.open("w", encoding="utf-8") as f:
            json.dump(kaggle_data, f)

        records = load_kaggle_pii_json(kaggle_file)
        assert len(records) == 1
        assert records[0].text == "First instance of document 2001."

    def test_duplicate_documents_deduplicated_in_csv_loader(self, tmp_path: Path):
        csv_file = tmp_path / "dupe_docs.csv"
        csv_content = (
            "document_id,text,spans_json\n"
            "dup_1,First copy of document,[]\n"
            "dup_1,Second copy of document,[]\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8")

        records = load_csv_dataset(csv_file)
        assert len(records) == 1
        assert records[0].text == "First copy of document"

