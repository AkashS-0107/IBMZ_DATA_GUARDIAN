"""Automated unit and integration tests for training pipeline and preprocessing modules.

Tests BIO annotation parsing, token text reconstruction, span validation,
deterministic document-level splitting, DocBin generation, and model training.
"""

import json
from pathlib import Path
import pytest
import spacy
from spacy.tokens import DocBin

from training.prepare_data import (
    bio_to_char_spans,
    normalize_label,
    process_kaggle_dataset,
    reconstruct_text_from_tokens,
    records_to_spacy_docbin,
    split_documents,
)
from training.train_model import train_pii_model


class TestDataPreprocessing:
    """Tests for text reconstruction, BIO conversion, and span validation."""

    def test_reconstruct_text_from_tokens_exact(self):
        tokens = ["Student", "Bob", "Smith", "submitted", "homework", "."]
        whitespace = [True, True, True, True, False, False]
        reconstructed = reconstruct_text_from_tokens(tokens, whitespace)
        assert reconstructed == "Student Bob Smith submitted homework."

    def test_reconstruct_text_mismatch_raises_safe_error(self):
        tokens = ["Word1", "Word2"]
        whitespace = [True]  # Mismatched length
        with pytest.raises(ValueError) as exc:
            reconstruct_text_from_tokens(tokens, whitespace)
        assert "Length mismatch" in str(exc.value)

    def test_normalize_label_canonical_mapping(self):
        assert normalize_label("B-NAME_STUDENT") == "NAME"
        assert normalize_label("I-NAME_STUDENT") == "NAME"
        assert normalize_label("B-EMAIL") == "EMAIL"
        assert normalize_label("B-PHONE_NUM") == "PHONE"
        assert normalize_label("B-URL_PERSONAL") == "PERSONAL_URL"
        assert normalize_label("B-ID_NUM") == "ID_NUMBER"
        assert normalize_label("B-STREET_ADDRESS") == "STREET_ADDRESS"
        assert normalize_label("B-USERNAME") == "USERNAME"
        # Unknown fallback
        assert normalize_label("CUSTOM_ENTITY") == "CUSTOM_ENTITY"

    def test_bio_to_char_spans_conversion(self):
        tokens = ["Email", "is", "alice@example.com", "for", "Jane", "Doe", "."]
        whitespace = [True, True, True, True, True, False, False]
        labels = ["O", "O", "B-EMAIL", "O", "B-NAME_STUDENT", "I-NAME_STUDENT", "O"]

        text, spans = bio_to_char_spans(tokens, whitespace, labels, doc_id="test_01")
        assert text == "Email is alice@example.com for Jane Doe."
        assert len(spans) == 2

        # First entity: EMAIL
        s1 = spans[0]
        assert s1["entity_type"] == "EMAIL"
        assert text[s1["start"]:s1["end"]] == "alice@example.com"

        # Second entity: NAME (multi-token student name)
        s2 = spans[1]
        assert s2["entity_type"] == "NAME"
        assert text[s2["start"]:s2["end"]] == "Jane Doe"

    def test_bio_consecutive_entities_of_same_type(self):
        # Two consecutive student names separated by space
        tokens = ["Contact", "Alice", "Bob", "."]
        whitespace = [True, True, False, False]
        labels = ["O", "B-NAME_STUDENT", "B-NAME_STUDENT", "O"]

        text, spans = bio_to_char_spans(tokens, whitespace, labels)
        assert len(spans) == 2
        assert text[spans[0]["start"]:spans[0]["end"]] == "Alice"
        assert text[spans[1]["start"]:spans[1]["end"]] == "Bob"

    def test_bio_malformed_i_tag_without_b_tag_repaired(self):
        # I- tag appearing without preceding B- tag
        tokens = ["Student", "Alice", "Smith", "."]
        whitespace = [True, True, False, False]
        labels = ["O", "I-NAME_STUDENT", "I-NAME_STUDENT", "O"]

        text, spans = bio_to_char_spans(tokens, whitespace, labels)
        assert len(spans) == 1
        assert spans[0]["entity_type"] == "NAME"
        assert text[spans[0]["start"]:spans[0]["end"]] == "Alice Smith"

    def test_bio_token_length_mismatch_raises_safe_error(self):
        tokens = ["Alice", "Smith"]
        whitespace = [True, False]
        labels = ["B-NAME_STUDENT"]  # Missing 1 label

        with pytest.raises(ValueError) as exc:
            bio_to_char_spans(tokens, whitespace, labels, doc_id="doc_bad")
        assert "Token length mismatch" in str(exc.value)

    def test_span_bounds_validation_and_out_of_bounds_rejection(self):
        tokens = ["Hello", "World"]
        whitespace = [True, False]
        labels = ["O", "O"]

        text, spans = bio_to_char_spans(tokens, whitespace, labels)
        assert spans == []
        assert text == "Hello World"


class TestDatasetSplitting:
    """Tests for document-level train/val/test splitting."""

    def test_deterministic_document_splitting_reproducibility(self):
        docs = [{"document_id": f"doc_{i}", "text": f"Text {i}"} for i in range(20)]

        train1, val1, test1 = split_documents(docs, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=123)
        train2, val2, test2 = split_documents(docs, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=123)

        assert [d["document_id"] for d in train1] == [d["document_id"] for d in train2]
        assert [d["document_id"] for d in val1] == [d["document_id"] for d in val2]
        assert [d["document_id"] for d in test1] == [d["document_id"] for d in test2]

    def test_document_level_isolation(self):
        docs = [{"document_id": f"doc_{i}", "text": f"Sample text {i}"} for i in range(30)]

        train, val, test = split_documents(docs, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, seed=42)

        train_ids = {d["document_id"] for d in train}
        val_ids = {d["document_id"] for d in val}
        test_ids = {d["document_id"] for d in test}

        # Zero document leakage across subsets
        assert train_ids.isdisjoint(val_ids)
        assert train_ids.isdisjoint(test_ids)
        assert val_ids.isdisjoint(test_ids)
        assert len(train_ids) + len(val_ids) + len(test_ids) == len(docs)

    def test_invalid_split_ratios_rejected(self):
        docs = [{"document_id": "d1", "text": "sample"}]
        with pytest.raises(ValueError) as exc:
            split_documents(docs, train_ratio=0.5, val_ratio=0.5, test_ratio=0.5)
        assert "must sum to 1.0" in str(exc.value)


class TestDocBinAndModelTraining:
    """Tests for spaCy DocBin conversion, training loop, and manifest generation."""

    def test_spacy_docbin_conversion_and_overlap_filtering(self):
        records = [
            {
                "document_id": "d_1",
                "text": "Call Jane Doe at 555-0199.",
                "spans": [
                    {"start": 5, "end": 13, "label": "NAME"},
                    {"start": 17, "end": 25, "label": "PHONE"},
                ],
            }
        ]
        nlp = spacy.blank("en")
        doc_bin = records_to_spacy_docbin(records, nlp)
        docs = list(doc_bin.get_docs(nlp.vocab))
        assert len(docs) == 1
        ents = [(e.text, e.label_) for e in docs[0].ents]
        assert ("Jane Doe", "NAME") in ents
        assert ("555-0199", "PHONE") in ents

    def test_end_to_end_synthetic_pipeline_execution(self, tmp_path: Path):
        # 1. Create a mini Kaggle-formatted JSON
        source_data = [
            {
                "document": 201,
                "tokens": ["Author", "Jane", "Doe", "contact", "jane@edu.org", "."],
                "trailing_whitespace": [True, True, True, True, False, False],
                "labels": ["O", "B-NAME_STUDENT", "I-NAME_STUDENT", "O", "B-EMAIL", "O"],
            },
            {
                "document": 202,
                "tokens": ["Student", "Carlos", "Mendez", "phone", "+1-555-0199", "."],
                "trailing_whitespace": [True, True, True, True, False, False],
                "labels": ["O", "B-NAME_STUDENT", "I-NAME_STUDENT", "O", "B-PHONE_NUM", "O"],
            },
            {
                "document": 203,
                "tokens": ["Residence", "123", "Main", "Street", "id", "999-88-7777", "."],
                "trailing_whitespace": [True, True, True, True, True, False, False],
                "labels": ["O", "B-STREET_ADDRESS", "I-STREET_ADDRESS", "I-STREET_ADDRESS", "O", "B-ID_NUM", "O"],
            },
        ]
        json_file = tmp_path / "raw_kaggle.json"
        with json_file.open("w", encoding="utf-8") as f:
            json.dump(source_data, f)

        # 2. Run preprocessing
        processed_dir = tmp_path / "processed"
        summary = process_kaggle_dataset(
            input_file=json_file,
            output_dir=processed_dir,
            train_ratio=0.34,
            val_ratio=0.33,
            test_ratio=0.33,
            seed=42,
        )
        assert summary["total_documents"] == 3
        assert (processed_dir / "train.spacy").is_file()
        assert (processed_dir / "val.spacy").is_file()
        assert (processed_dir / "test.spacy").is_file()

        # 3. Run 1-epoch quick training
        model_dir = tmp_path / "model"
        manifest = train_pii_model(
            train_data_path=processed_dir / "train.spacy",
            val_data_path=processed_dir / "val.spacy",
            output_dir=model_dir,
            epochs=1,
            batch_size=2,
            seed=42,
        )

        assert manifest["model_type"] == "spacy_blank_en_ner"
        assert manifest["training_seed"] == 42
        assert (model_dir / "config.cfg").is_file()
        assert (model_dir / "manifest.json").is_file()
        assert "epoch_history" in manifest
        assert manifest["sample_counts"]["train_documents"] >= 1
