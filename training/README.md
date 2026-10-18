# Training & Model Integration Pipeline

This directory contains the machine learning training pipeline for contextual Personally Identifiable Information (PII) entity detection in **AI Data Leak Guardian**, developed for the IBM Z hackathon challenge *"AI Secured: Innovation Without Exposure"*.

The ML detector is built as a lightweight, CPU-trainable spaCy English Named Entity Recognition (NER) pipeline designed to complement the deterministic rule-based secret detector and Shannon entropy heuristics.

---

## 1. Dataset Source & Setup Instructions

### Primary Dataset
- **Name:** The Learning Agency Lab - PII Data Detection
- **Competition URL:** [https://www.kaggle.com/competitions/pii-detection-removal-from-educational-data/data](https://www.kaggle.com/competitions/pii-detection-removal-from-educational-data/data)
- **Files:** `train.json` (~6,800 educational essays with token-level BIO labels), `test.json` (unlabeled).

### Kaggle Access & Authentication
1. Create or log in to your account on [Kaggle](https://www.kaggle.com).
2. Go to the competition page and review/accept the Official Competition Rules and terms of service.
3. Obtain your Kaggle API key from your profile (`Account -> API -> Create New API Token`), which downloads `kaggle.json`.
4. Place `kaggle.json` in your user directory:
   - Linux/macOS/LinuxONE: `~/.kaggle/kaggle.json`
   - Windows: `%USERPROFILE%\.kaggle\kaggle.json`
   - Set restrictive permissions (`chmod 600 ~/.kaggle/kaggle.json` on Unix).
   > **Security Note:** Never commit `kaggle.json` to Git or expose credentials in logs or source code.
5. Download the competition dataset:
   ```bash
   kaggle competitions download -c pii-detection-removal-from-educational-data -p datasets/raw/
   unzip datasets/raw/pii-detection-removal-from-educational-data.zip -d datasets/raw/
   ```
6. The primary training file will be located at: `datasets/raw/train.json`.

### Synthetic Offline Fixture
If Kaggle access is unavailable, the pipeline can be executed immediately using the offline synthetic Kaggle fixture provided in `fixtures/synthetic_kaggle_data.json`.

---

## 2. Dataset Schema & Label Normalization

### Kaggle Input Schema (`train.json`)
Each entry in the Kaggle training dataset is a JSON object with:
- `document`: Unique integer document ID.
- `full_text`: Raw unredacted essay text.
- `tokens`: List of whitespace-delimited word tokens.
- `trailing_whitespace`: List of boolean flags indicating trailing space after each token.
- `labels`: BIO tag sequence (`O`, `B-NAME_STUDENT`, `I-NAME_STUDENT`, etc.).

### Entity Label Mapping
BIO labels from the Kaggle schema are normalized into the unified `EntityType` taxonomy:

| Kaggle Label | Canonical EntityType | System Severity | Description |
| :--- | :--- | :--- | :--- |
| `NAME_STUDENT` | `NAME` | Medium | Student and individual names |
| `EMAIL` | `EMAIL` | Medium | Electronic mail addresses |
| `PHONE_NUM` | `PHONE` | High | Telephone numbers |
| `URL_PERSONAL` | `PERSONAL_URL` | Low | Personal portfolio & social links |
| `ID_NUM` | `ID_NUMBER` | High | National/student identification numbers |
| `STREET_ADDRESS` | `STREET_ADDRESS` | High | Physical mailing and street addresses |
| `USERNAME` | `USERNAME` | Medium | Online system and platform usernames |

---

## 3. Preprocessing Workflow (`training/prepare_data.py`)

The data preparation module performs:
1. **Document Text Reconstruction:** Validates token character offsets using `tokens` and `trailing_whitespace`.
2. **BIO to Character Span Conversion:** Resolves `B-` (begin), `I-` (inside), and `O` (outside) tokens into `[start, end)` half-open character intervals.
3. **Span Verification:** Ensures every span indexes the exact token string in the document text.
4. **Document-Level Split Isolation:** Shuffles documents using a deterministic seed (`42`) and partitions into Train (80%), Validation (10%), and Test (10%). **Document IDs are strictly partitioned to eliminate data leakage.**
5. **spaCy DocBin Serialization:** Converts spans to token-aligned spans using `spacy.util.filter_spans` to eliminate any overlapping entities, writing `train.spacy`, `val.spacy`, and `test.spacy`.

### Preprocessing Command
```bash
# With official Kaggle data:
python training/prepare_data.py --input datasets/raw/train.json --output-dir datasets/processed --seed 42

# Or with offline synthetic fixture:
python training/prepare_data.py --input fixtures/synthetic_kaggle_data.json --output-dir datasets/processed --seed 42
```

Outputs in `datasets/processed/`:
- `train.spacy`: Serialized training dataset.
- `val.spacy`: Validation dataset for checkpoint tuning.
- `test.spacy`: Held-out test dataset for benchmark scoring.
- `test_records.jsonl`: Benchmark test records.
- `data_summary.json`: Partition counts and entity distributions.

---

## 4. Model Architecture & Hyperparameters

- **Architecture:** Lightweight transition-based Named Entity Recognition (NER) component added to a blank English spaCy pipeline (`spacy.blank("en")`).
- **Device:** CPU (no GPU required).
- **Hyperparameters:**
  - Initial learning rate: `0.001`
  - Optimizer: Adam with linear warmup (`spacy.initialize()`)
  - Minibatch size: `8` (compound batching)
  - Dropout: `0.20`
  - Default Epochs: `10`–`15`
  - Random Seed: `42` (`spacy.util.fix_random_seed(42)`)

### Training Command (`training/train_model.py`)
```bash
python training/train_model.py \
    --train-data datasets/processed/train.spacy \
    --val-data datasets/processed/val.spacy \
    --output-dir models/pii_ner \
    --epochs 10 \
    --seed 42
```

Outputs in `models/pii_ner/`:
- `config.cfg`: spaCy pipeline configuration.
- `ner/`: Serialized model weights and transition tables.
- `vocab/`: Vocabulary strings and lexeme tables.
- `manifest.json`: Artifact manifest detailing Python version, spaCy version, hyperparameters, validation metrics, duration, and artifact size. **Contains zero raw sensitive data.**

---

## 5. Evaluation Command & Methodology (`training/evaluate_model.py`)

Evaluates performance on the held-out test subset under exact-span matching rules:
1. **Mode 1 (ML Alone):** Evaluates `MLPIIDetector` predictions in isolation.
2. **Mode 2 (Rules Alone):** Evaluates regex and heuristic rules without ML.
3. **Mode 3 (Combined Hybrid):** Evaluates the integrated detector with deterministic overlap resolution.

### Evaluation Command
```bash
python training/evaluate_model.py \
    --test-data datasets/processed/test_records.jsonl \
    --model-dir models/pii_ner \
    --policy exact-span \
    --output-report models/pii_ner/evaluation_report.json
```

---

## 6. Hybrid Detection Architecture & Conflict Resolution

The system employs a 3-tier defense-in-depth architecture:

1. **Deterministic Rule Detector:** High-precision regex patterns for emails, phones, IPs, and **Critical credentials** (passwords, private keys, API keys, bearer tokens, connection strings).
2. **Contextual ML Detector:** spaCy NER model for contextual entities (student names, usernames, street addresses, personal profile links).
3. **Shannon Entropy Heuristics:** High-entropy token scanner for unstructured candidate secrets ($H \ge 3.6$ bits/char).

### Deterministic Overlap Resolution Policy
When spans overlap, conflicts are resolved in strict priority order:
1. **Severity Rank:** Critical credentials (Severity 4) strictly override High/Medium PII. A model trained on student essays cannot suppress passwords or API keys.
2. **Source Precedence:** Deterministic rules (`secret:*`, `regex:*`) > Contextual rules (`context:*`) > ML model (`ml:*`) > Entropy (`heuristic:*`).
3. **Span Length:** Longer matches win when severities and sources are equal.
4. **Offset:** Earlier start offset breaks any remaining tie.
5. **Deduplication:** Identical findings from rules and ML on the same span are merged into a single finding.

### Rules-Only Mode Fallback
If the model artifacts are not present or `ML_ENABLED = False` in `config.py`, the system logs an audit-safe notice and operates in rules-only fallback mode. Rule-based security checks are never disabled or bypassed by ML availability.

---

## 7. Inference Interface (`training/predict.py`)

### Programmatic Usage
```python
from training.predict import MLPIIDetector

detector = MLPIIDetector(model_path="models/pii_ner", confidence_threshold=0.50)
if detector.is_available():
    findings = detector.detect("Essay submitted by Carlos Mendez at 742 Evergreen Terrace.")
    for f in findings:
        print(f"Detected {f.entity_type.value} at [{f.start}, {f.end})")
```

### CLI Inference
```bash
python training/predict.py --model-dir models/pii_ner --text "Student Bob Smith submitted homework."
```

---

## 8. Measured Performance & Resource Profile

Measurements conducted on CPU:
- **Training Duration:** ~0.96 seconds (synthetic dataset, 10 epochs).
- **Inference Latency:** **~1.21 ms per document** (measured across 100 consecutive calls on CPU).
- **Model Artifact Size:** **~3.76 MB** (self-contained spaCy NER pipeline).
- **Memory Footprint:** Well within the 8 GB RAM envelope (< 250 MB RSS during training and inference).

---

## 9. IBM LinuxONE (s390x) Compatibility Considerations

The project will deploy to an Ubuntu VM with 3 vCPUs and 8 GB RAM on IBM LinuxONE (IBM z16 architecture, big-endian `s390x`).

### Architecture Status & Guidelines:
1. **CPU Execution:** The model uses standard CPU vector operations without CUDA or GPU dependencies, matching LinuxONE capabilities.
2. **Byte-Order Compatibility:** spaCy serialization (`DocBin` and `to_disk`) uses platform-independent msgpack and binary weights. However, binary wheels must be built or installed for the `s390x` architecture.
3. **Pre-flight Validation:** When deploying on LinuxONE:
   - Install `spacy` via pip using s390x compatible wheels or compile with GCC: `pip install spacy`.
   - Run the full offline test suite: `pytest`.
   - Validate model loading: `python -m training.predict --model-dir models/pii_ner --text "Health check"`.
4. **Zero Cloud Dependencies:** Training and inference run 100% locally with zero external network calls.
