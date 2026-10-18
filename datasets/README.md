# Datasets Directory

This directory stores datasets for evaluating the AI Data Leak Guardian detection and redaction engine.

## Structure
- `raw/`: Unprocessed source datasets (e.g. downloaded Kaggle archives). **Not tracked in Git.**
- `processed/`: Standardized dataset records in normalized format. **Not tracked in Git.**

## Primary Permitted Dataset
**The Learning Agency Lab - PII Data Detection**
- Kaggle Competition: [pii-detection-removal-from-educational-data](https://www.kaggle.com/competitions/pii-detection-removal-from-educational-data/data)
- License: Subject to Kaggle Competition Rules and Kaggle Terms of Service.
- Access: Requires Kaggle user account and accepting competition rules.

## Synthetic Fixtures
For automated CI/CD and offline testing without Kaggle access, deterministic synthetic fixtures are provided in `fixtures/`:
- `fixtures/synthetic_pii.jsonl`
- `fixtures/synthetic_secrets.jsonl`
