# Model Artifacts Directory

This directory stores trained NER model checkpoints and evaluation manifests for the AI Data Leak Guardian.

## Structure
- `pii_ner/`: Directory containing the trained spaCy pipeline and `manifest.json`.
- Model weight binaries and checkpoints (`*.spacy`, serialized pipeline components) are **excluded from Git** to prevent repository bloat and ensure privacy compliance.

## Reproducibility
Model weights are generated reproducibly using `training/train_model.py` with fixed random seeds. See `training/README.md` for full instructions.
