"""Dataset preprocessing and conversion pipeline for PII model training.

Parses Kaggle 'The Learning Agency Lab - PII Data Detection' competition data,
reconstructs text from tokens and trailing whitespace, converts BIO annotations
into validated character-level spans, normalizes entity labels, performs reproducible
document-level train/validation/test splitting, and outputs spaCy DocBin archives.

All malformed or unaligned examples are audited safely without logging raw PII.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import spacy
from spacy.tokens import DocBin, Span
from spacy.util import filter_spans

# Configure audit-safe logger
logger = logging.getLogger("prepare_data")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)


# Standard normalization map from Kaggle BIO tags to unified EntityType taxonomy
KAGGLE_BIO_LABEL_MAP: Dict[str, str] = {
    "NAME_STUDENT": "NAME",
    "EMAIL": "EMAIL",
    "PHONE_NUM": "PHONE",
    "URL_PERSONAL": "PERSONAL_URL",
    "ID_NUM": "ID_NUMBER",
    "STREET_ADDRESS": "STREET_ADDRESS",
    "USERNAME": "USERNAME",
}


def reconstruct_text_from_tokens(tokens: List[str], trailing_whitespace: List[bool]) -> str:
    """Reconstruct document text strictly from token strings and trailing whitespace flags.

    Matches Kaggle competition document reconstruction formula:
    "".join(t + (" " if ws else "") for t, ws in zip(tokens, trailing_whitespace))
    """
    if len(tokens) != len(trailing_whitespace):
        raise ValueError(
            f"Length mismatch: tokens ({len(tokens)}) != trailing_whitespace ({len(trailing_whitespace)})"
        )
    return "".join(token + (" " if ws else "") for token, ws in zip(tokens, trailing_whitespace))


def normalize_label(raw_tag: str) -> str:
    """Normalize Kaggle entity tag to canonical taxonomy."""
    # Strip B- or I- prefix if present
    clean_tag = raw_tag[2:] if raw_tag.startswith(("B-", "I-")) else raw_tag
    return KAGGLE_BIO_LABEL_MAP.get(clean_tag, clean_tag.upper())


def bio_to_char_spans(
    tokens: List[str],
    trailing_whitespace: List[bool],
    labels: List[str],
    full_text: Optional[str] = None,
    doc_id: Optional[str] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Convert BIO token sequences to verified character-level entity spans.

    Returns:
        Tuple of (reconstructed_or_verified_text, list_of_validated_spans).
    Raises:
        ValueError if lengths mismatch or inputs are malformed.
    """
    if not (len(tokens) == len(trailing_whitespace) == len(labels)):
        raise ValueError(
            f"Token length mismatch in doc {doc_id or 'unknown'}: "
            f"tokens={len(tokens)}, whitespace={len(trailing_whitespace)}, labels={len(labels)}"
        )

    # Reconstruct text from tokens and trailing whitespace
    reconstructed = reconstruct_text_from_tokens(tokens, trailing_whitespace)

    # Use reconstructed text or full_text if exact match
    text = full_text if full_text is not None and full_text == reconstructed else reconstructed

    # Calculate token character offsets [start, end)
    token_offsets: List[Tuple[int, int]] = []
    cursor = 0
    for tok, ws in zip(tokens, trailing_whitespace):
        tok_len = len(tok)
        start = cursor
        end = start + tok_len
        token_offsets.append((start, end))
        cursor = end + (1 if ws else 0)

    # Parse BIO tags into character spans
    raw_spans: List[Dict[str, Any]] = []
    current_label: Optional[str] = None
    current_start: Optional[int] = None
    current_end: Optional[int] = None
    current_token_count = 0

    for idx, (label, (t_start, t_end)) in enumerate(zip(labels, token_offsets)):
        if label.startswith("B-"):
            if current_label is not None and current_start is not None and current_end is not None:
                raw_spans.append({
                    "entity_type": current_label,
                    "start": current_start,
                    "end": current_end,
                    "token_count": current_token_count,
                })
            current_label = normalize_label(label)
            current_start = t_start
            current_end = t_end
            current_token_count = 1

        elif label.startswith("I-"):
            norm_label = normalize_label(label)
            if current_label == norm_label and current_start is not None:
                # Extend current span
                current_end = t_end
                current_token_count += 1
            else:
                # Malformed I- tag without preceding B- or label mismatch: repair by starting new span
                if current_label is not None and current_start is not None and current_end is not None:
                    raw_spans.append({
                        "entity_type": current_label,
                        "start": current_start,
                        "end": current_end,
                        "token_count": current_token_count,
                    })
                current_label = norm_label
                current_start = t_start
                current_end = t_end
                current_token_count = 1

        else:  # "O" or other label
            if current_label is not None and current_start is not None and current_end is not None:
                raw_spans.append({
                    "entity_type": current_label,
                    "start": current_start,
                    "end": current_end,
                    "token_count": current_token_count,
                })
                current_label = None
                current_start = None
                current_end = None
                current_token_count = 0

    # Add final open span
    if current_label is not None and current_start is not None and current_end is not None:
        raw_spans.append({
            "entity_type": current_label,
            "start": current_start,
            "end": current_end,
            "token_count": current_token_count,
        })

    # Validate each span points to valid non-empty text within bounds
    validated_spans: List[Dict[str, Any]] = []
    text_len = len(text)
    for s_idx, span in enumerate(raw_spans):
        start = span["start"]
        end = span["end"]
        if not (0 <= start < end <= text_len):
            logger.warning(
                "Safe audit: Span #%d in doc %s out of bounds [0, %d). Skipping.",
                s_idx, doc_id or "unknown", text_len
            )
            continue

        target_slice = text[start:end]
        if not target_slice.strip():
            logger.warning(
                "Safe audit: Span #%d in doc %s spans only whitespace. Skipping.",
                s_idx, doc_id or "unknown"
            )
            continue

        validated_spans.append({
            "entity_type": span["entity_type"],
            "start": start,
            "end": end,
            "label": span["entity_type"],
        })

    return text, validated_spans


def split_documents(
    documents: List[Dict[str, Any]],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Reproducibly split documents into train, validation, and test subsets.

    Splits strictly by whole document (NOT individual tokens or sentences) to
    prevent contextual leakage between subsets.
    """
    total_ratio = train_ratio + val_ratio + test_ratio
    if abs(total_ratio - 1.0) > 1e-4:
        raise ValueError(
            f"Split ratios must sum to 1.0, got train={train_ratio}, val={val_ratio}, test={test_ratio}"
        )

    if not documents:
        return [], [], []

    # Copy and shuffle with isolated deterministic random generator
    rng = random.Random(seed)
    shuffled = list(documents)
    rng.shuffle(shuffled)

    n_total = len(shuffled)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)

    # In edge cases with very few documents, guarantee at least 1 document per split if total >= 3
    if n_total >= 3:
        if n_train == 0:
            n_train = 1
        if n_val == 0:
            n_val = 1
        if (n_train + n_val) >= n_total:
            n_train = max(1, n_total - 2)
            n_val = 1

    train_docs = shuffled[:n_train]
    val_docs = shuffled[n_train:n_train + n_val]
    test_docs = shuffled[n_train + n_val:]

    # Assert strict document ID isolation
    train_ids = {str(d.get("document", d.get("document_id", id(d)))) for d in train_docs}
    val_ids = {str(d.get("document", d.get("document_id", id(d)))) for d in val_docs}
    test_ids = {str(d.get("document", d.get("document_id", id(d)))) for d in test_docs}

    if (train_ids & val_ids) or (train_ids & test_ids) or (val_ids & test_ids):
        raise RuntimeError("Document isolation failure: overlapping document IDs across splits")

    return train_docs, val_docs, test_docs


def records_to_spacy_docbin(
    records: List[Dict[str, Any]],
    nlp: Optional[spacy.Language] = None,
) -> DocBin:
    """Convert normalized dataset records into a serialized spaCy DocBin.

    Handles token boundary alignment and resolves overlapping entity spans.
    """
    nlp = nlp or spacy.blank("en")
    doc_bin = DocBin(attrs=["ENT_IOB", "ENT_TYPE"], store_user_data=True)

    for rec in records:
        text = rec["text"]
        spans = rec.get("spans", rec.get("ground_truth", []))
        doc = nlp.make_doc(text)

        valid_spans: List[Span] = []
        for s in spans:
            start = s["start"] if isinstance(s, dict) else s.start
            end = s["end"] if isinstance(s, dict) else s.end
            label = s["label"] if isinstance(s, dict) else (s.label or s.entity_type)

            # Alignment mode 'contract' snaps strictly inside token boundaries
            char_span = doc.char_span(start, end, label=label, alignment_mode="contract")
            if char_span is None:
                # Fallback to 'expand' if token boundary slightly touches whitespace
                char_span = doc.char_span(start, end, label=label, alignment_mode="expand")

            if char_span is not None:
                valid_spans.append(char_span)

        # Filter overlapping spans (longest span wins)
        non_overlapping = filter_spans(valid_spans)
        doc.ents = non_overlapping
        doc_bin.add(doc)

    return doc_bin


def process_kaggle_dataset(
    input_file: str | Path,
    output_dir: str | Path,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42,
    sample_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute full preprocessing pipeline from raw Kaggle JSON to prepared train/val/test splits."""
    input_path = Path(input_file)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.is_file():
        raise FileNotFoundError(f"Source dataset not found at {input_path}")

    with input_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected list of document objects, got {type(data).__name__}")

    if sample_size and sample_size < len(data):
        data = data[:sample_size]

    logger.info("Parsing and validating %d source documents from %s", len(data), input_path.name)

    normalized_records: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    entity_counts: Dict[str, int] = {}

    for doc_idx, doc_item in enumerate(data):
        doc_id = str(doc_item.get("document", doc_item.get("document_id", f"doc_{doc_idx}")))
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)

        tokens = doc_item.get("tokens", [])
        ws = doc_item.get("trailing_whitespace", [])
        labels = doc_item.get("labels", [])
        full_text = doc_item.get("full_text")

        text, spans = bio_to_char_spans(
            tokens=tokens,
            trailing_whitespace=ws,
            labels=labels,
            full_text=full_text,
            doc_id=doc_id,
        )

        for s in spans:
            etype = s["entity_type"]
            entity_counts[etype] = entity_counts.get(etype, 0) + 1

        normalized_records.append({
            "document_id": doc_id,
            "text": text,
            "spans": spans,
            "metadata": {"token_count": len(tokens), "source": "kaggle_pii_preprocessed"},
        })

    # Perform reproducible document-level split
    train_recs, val_recs, test_recs = split_documents(
        normalized_records,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
    )

    logger.info(
        "Split %d records into: train=%d, val=%d, test=%d (seed=%d)",
        len(normalized_records), len(train_recs), len(val_recs), len(test_recs), seed
    )

    # Convert to spaCy DocBin
    nlp = spacy.blank("en")
    train_bin = records_to_spacy_docbin(train_recs, nlp)
    val_bin = records_to_spacy_docbin(val_recs, nlp)
    test_bin = records_to_spacy_docbin(test_recs, nlp)

    # Save spaCy DocBins
    train_bin.to_disk(out_dir / "train.spacy")
    val_bin.to_disk(out_dir / "val.spacy")
    test_bin.to_disk(out_dir / "test.spacy")

    # Save normalized JSONL for evaluation and benchmark scripts
    def _write_jsonl(recs: List[Dict[str, Any]], path: Path) -> None:
        with path.open("w", encoding="utf-8") as jf:
            for r in recs:
                jf.write(json.dumps(r) + "\n")

    _write_jsonl(train_recs, out_dir / "train_records.jsonl")
    _write_jsonl(val_recs, out_dir / "val_records.jsonl")
    _write_jsonl(test_recs, out_dir / "test_records.jsonl")

    summary = {
        "source_file": str(input_path),
        "total_documents": len(normalized_records),
        "train_count": len(train_recs),
        "val_count": len(val_recs),
        "test_count": len(test_recs),
        "split_ratios": {"train": train_ratio, "val": val_ratio, "test": test_ratio},
        "seed": seed,
        "entity_counts": entity_counts,
        "artifacts": {
            "train_spacy": str(out_dir / "train.spacy"),
            "val_spacy": str(out_dir / "val.spacy"),
            "test_spacy": str(out_dir / "test.spacy"),
            "test_records_jsonl": str(out_dir / "test_records.jsonl"),
        },
    }

    with (out_dir / "data_summary.json").open("w", encoding="utf-8") as sf:
        json.dump(summary, sf, indent=2)

    logger.info("Saved DocBin and JSONL artifacts to %s", out_dir)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preprocess Kaggle PII dataset into reproducible train/val/test spaCy DocBins"
    )
    parser.add_argument(
        "--input", "-i", type=str, default="fixtures/synthetic_kaggle_data.json",
        help="Path to source Kaggle train.json or synthetic JSON fixture"
    )
    parser.add_argument(
        "--output-dir", "-o", type=str, default="datasets/processed",
        help="Directory to save preprocessed DocBin and JSONL files"
    )
    parser.add_argument(
        "--train-ratio", type=float, default=0.8, help="Train split ratio (default: 0.8)"
    )
    parser.add_argument(
        "--val-ratio", type=float, default=0.1, help="Validation split ratio (default: 0.1)"
    )
    parser.add_argument(
        "--test-ratio", type=float, default=0.1, help="Test split ratio (default: 0.1)"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for document split (default: 42)"
    )
    parser.add_argument(
        "--sample-size", type=int, default=None, help="Optional maximum documents to process"
    )

    args = parser.parse_args()
    process_kaggle_dataset(
        input_file=args.input,
        output_dir=args.output_dir,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
        seed=args.seed,
        sample_size=args.sample_size,
    )


if __name__ == "__main__":
    main()
