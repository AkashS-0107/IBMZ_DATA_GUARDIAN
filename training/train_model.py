"""Model training pipeline for contextual PII detection.

Trains a lightweight, CPU-friendly spaCy English NER model from Kaggle PII annotations.
Uses document-level validation evaluation, early saving of best checkpoint,
isolated reproducible random seeds, and produces a comprehensive manifest.json
without logging raw sensitive spans.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import spacy
from spacy.scorer import Scorer
from spacy.tokens import DocBin
from spacy.training import Example
from spacy.util import filter_spans, fix_random_seed, minibatch

from training.prepare_data import KAGGLE_BIO_LABEL_MAP

# Audit-safe logging
logger = logging.getLogger("train_model")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)


def evaluate_examples(
    nlp: spacy.Language,
    examples: List[Example]
) -> Dict[str, float]:
    """Evaluate current model state on validation examples."""
    if not examples:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    pred_examples: List[Example] = []
    for ex in examples:
        pred_doc = nlp(ex.reference.text)
        pred_ex = Example(pred_doc, ex.reference)
        pred_examples.append(pred_ex)

    scorer = Scorer()
    scores = scorer.score(pred_examples)
    ents_p = scores.get("ents_p", 0.0) or 0.0
    ents_r = scores.get("ents_r", 0.0) or 0.0
    ents_f = scores.get("ents_f", 0.0) or 0.0

    return {
        "precision": round(ents_p, 4),
        "recall": round(ents_r, 4),
        "f1": round(ents_f, 4),
    }


def train_pii_model(
    train_data_path: str | Path,
    val_data_path: str | Path,
    output_dir: str | Path,
    epochs: int = 15,
    batch_size: int = 8,
    dropout: float = 0.2,
    lr: float = 0.001,
    seed: int = 42,
    dataset_source: Optional[str] = None,
) -> Dict[str, Any]:
    """Train a CPU-friendly spaCy NER model on preprocessed DocBin files."""
    train_path = Path(train_data_path)
    val_path = Path(val_data_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not train_path.is_file():
        raise FileNotFoundError(f"Training DocBin not found at: {train_path}")
    if not val_path.is_file():
        raise FileNotFoundError(f"Validation DocBin not found at: {val_path}")

    # Set deterministic random seed
    fix_random_seed(seed)
    random.seed(seed)

    start_time = time.perf_counter()

    # Initialize blank English pipeline
    nlp = spacy.blank("en")
    ner = nlp.add_pipe("ner")

    # Load DocBins
    train_bin = DocBin().from_disk(train_path)
    val_bin = DocBin().from_disk(val_path)

    train_docs = list(train_bin.get_docs(nlp.vocab))
    val_docs = list(val_bin.get_docs(nlp.vocab))

    # Convert to Examples and register labels
    train_examples: List[Example] = []
    labels_seen: set[str] = set()
    for doc in train_docs:
        gold_entities = [(e.start_char, e.end_char, e.label_) for e in doc.ents]
        for _, _, lbl in gold_entities:
            ner.add_label(lbl)
            labels_seen.add(lbl)
        ex = Example.from_dict(nlp.make_doc(doc.text), {"entities": gold_entities})
        train_examples.append(ex)

    val_examples: List[Example] = []
    for doc in val_docs:
        gold_entities = [(e.start_char, e.end_char, e.label_) for e in doc.ents]
        for _, _, lbl in gold_entities:
            ner.add_label(lbl)
            labels_seen.add(lbl)
        ex = Example.from_dict(nlp.make_doc(doc.text), {"entities": gold_entities})
        val_examples.append(ex)

    logger.info(
        "Initializing spaCy NER with %d registered entity labels across %d train / %d val docs",
        len(labels_seen), len(train_examples), len(val_examples)
    )

    optimizer = nlp.initialize(lambda: train_examples)
    if hasattr(optimizer, "learn_rate"):
        optimizer.learn_rate = lr

    best_val_f1 = -1.0
    best_val_metrics: Dict[str, float] = {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    epoch_history: List[Dict[str, Any]] = []

    for epoch in range(1, epochs + 1):
        epoch_rng = random.Random(seed + epoch)
        shuffled_train = list(train_examples)
        epoch_rng.shuffle(shuffled_train)

        losses: Dict[str, float] = {}
        batches = minibatch(shuffled_train, size=batch_size)
        for batch in batches:
            nlp.update(batch, drop=dropout, sgd=optimizer, losses=losses)

        # Validation evaluation
        val_metrics = evaluate_examples(nlp, val_examples)
        train_loss = round(float(losses.get("ner", 0.0)), 4)

        epoch_record = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_precision": val_metrics["precision"],
            "val_recall": val_metrics["recall"],
            "val_f1": val_metrics["f1"],
        }
        epoch_history.append(epoch_record)

        logger.info(
            "Epoch %d/%d - Loss: %.4f | Val Precision: %.4f | Val Recall: %.4f | Val F1: %.4f",
            epoch, epochs, train_loss, val_metrics["precision"], val_metrics["recall"], val_metrics["f1"]
        )

        # Checkpoint if validation improved or first epoch
        if val_metrics["f1"] >= best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_val_metrics = val_metrics
            nlp.to_disk(out_dir)

    # Ensure model is saved even if metrics were 0.0 on tiny validation fixture
    if not (out_dir / "config.cfg").exists():
        nlp.to_disk(out_dir)

    duration = round(time.perf_counter() - start_time, 2)
    logger.info("Training complete in %.2f seconds. Best Val F1: %.4f", duration, best_val_f1)

    # Calculate model artifact size
    total_bytes = sum(f.stat().st_size for f in out_dir.rglob("*") if f.is_file())
    size_mb = round(total_bytes / (1024 * 1024), 2)

    # Write artifact manifest
    manifest = {
        "model_type": "spacy_blank_en_ner",
        "pipeline": ["ner"],
        "python_version": sys.version.split()[0],
        "spacy_version": spacy.__version__,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "training_seed": seed,
        "dataset_source": dataset_source or str(train_path),
        "hyperparameters": {
            "epochs": epochs,
            "batch_size": batch_size,
            "dropout": dropout,
            "learning_rate": lr,
        },
        "sample_counts": {
            "train_documents": len(train_examples),
            "validation_documents": len(val_examples),
        },
        "registered_labels": sorted(labels_seen),
        "label_mapping": KAGGLE_BIO_LABEL_MAP,
        "validation_metrics": best_val_metrics,
        "training_duration_seconds": duration,
        "artifact_size_mb": size_mb,
        "artifact_path": str(out_dir.resolve()),
        "epoch_history": epoch_history,
    }

    manifest_path = out_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    logger.info("Manifest saved safely to %s (Size: %.2f MB)", manifest_path, size_mb)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train lightweight spaCy NER model for PII entity detection"
    )
    parser.add_argument(
        "--train-data", type=str, default="datasets/processed/train.spacy",
        help="Path to training DocBin file"
    )
    parser.add_argument(
        "--val-data", type=str, default="datasets/processed/val.spacy",
        help="Path to validation DocBin file"
    )
    parser.add_argument(
        "--output-dir", "-o", type=str, default="models/pii_ner",
        help="Directory to save trained spaCy model and manifest"
    )
    parser.add_argument(
        "--epochs", type=int, default=15, help="Number of training epochs (default: 15)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=8, help="Minibatch size (default: 8)"
    )
    parser.add_argument(
        "--dropout", type=float, default=0.2, help="Dropout rate (default: 0.2)"
    )
    parser.add_argument(
        "--lr", type=float, default=0.001, help="Learning rate (default: 0.001)"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)"
    )

    args = parser.parse_args()
    train_pii_model(
        train_data_path=args.train_data,
        val_data_path=args.val_data,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        dropout=args.dropout,
        lr=args.lr,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
