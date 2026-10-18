# AI Data Leak Guardian 🛡️
> **AI Secured: Innovation Without Exposure** | IBM Z Datathon & Hackathon Challenge

AI Data Leak Guardian is a privacy and security engine designed to detect sensitive information (PII and credentials) in user-provided text, assess exposure risk, deterministically redact sensitive values prior to forwarding prompts to external AI systems, and restore placeholders locally in returned responses.

---

## 1. System Architecture

The application is structured into modular, decoupled security components:

```
                      +-----------------------------+
                      |       Raw User Input        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |         detector.py         |
                      |   - Regex PII & Secrets     |
                      |   - Shannon Entropy Heuristic|
                      |   - Contextual spaCy NER    |
                      |   - Overlap Priority Engine |
                      +--------------+--------------+
                                     |
                         Structured Findings
                                     |
            +------------------------+------------------------+
            |                                                 |
            v                                                 v
+-----------------------+                         +-----------------------+
|        risk.py        |                         |      redactor.py      |
| - 4-Tier Classification|                        | - Right-to-Left Splicing|
| - Deterministic Rules |                         | - In-Memory Vault     |
| - Safe Audit Trail    |                         | - Collision Avoidance |
+-----------------------+                         +-----------+-----------+
                                                              |
                                                    Masked Prompt (Placeholders)
                                                              |
                                                              v
                                                   [ External AI Engine ]
                                                              |
                                                    Masked AI Response
                                                              |
                                                              v
                                                  +-----------------------+
                                                  |   Local Restoration   |
                                                  | - Session-Scoped Map  |
                                                  | - Non-Executing Text  |
                                                  +-----------+-----------+
                                                              |
                                                              v
                                                   Clean Restored Response
```

### Core Components
1. **`detector.py`**:
   - **PII Detector**: Recognizes RFC 5322 emails, E.164 international phone numbers, IPv4/IPv6 addresses, personal profile URLs (LinkedIn, GitHub), US SSNs, and contextual names.
   - **Contextual ML Detector (`training/predict.py`)**: Trained CPU-friendly spaCy English NER pipeline detecting student names, personal URLs, IDs, usernames, and street addresses. Automatically falls back to rules-only mode if the model is absent.
   - **Secret Detector**: Recognizes password assignments, Bearer authorization tokens, generic API keys, database connection strings (PostgreSQL, MySQL, MongoDB), cryptographic private key blocks (PEM format), and cloud credentials (AWS Access Keys, GitHub Tokens, Slack Tokens).
   - **Shannon Entropy Detector**: Calculates informational entropy ($H(X) = -\sum p(x) \log_2 p(x)$) over alphanumeric tokens, filtering ordinary programming identifiers while capturing high-entropy candidate secrets.
   - **Deterministic Overlap Resolution**: Sorts candidates by severity rank (`CRITICAL > HIGH > MEDIUM > LOW`), source priority (deterministic rules > contextual rules > ML model > entropy), and span length, guaranteeing credentials are never discarded for lower-severity PII.
2. **`risk.py`**:
   - Evaluates findings into 4 deterministic tiers: **Low**, **Medium**, **High**, or **Critical**.
   - Enforces secret priority: any confirmed credential immediately triggers `Critical` risk.
   - Provides safe, explainable audit rationales without exposing raw sensitive strings.
3. **`redactor.py`**:
   - Reversible placeholder substitution (`[EMAIL_1]`, `[API_KEY_1]`).
   - Slices strings right-to-left using 0-based half-open intervals `[start, end)`.
   - Reuses identical placeholders for repeated values within the same session.
   - Defends against collisions with pre-existing literal placeholder tokens in user input.
   - **In-Memory Vault**: Stores raw values strictly in process memory; never persists to disk, database, or logs. Provides explicit `.clear()` for zero-trace purging, and `restore_detailed()` returning structured `RestorationResult` audit detail.
4. **`frontend.py`**:
   - Streamlit-powered dark security dashboard (navy/charcoal/cyan palette).
   - Native session-state synchronization with isolated in-memory vaults.
   - Stale finding suppression: hides old findings when input is edited until re-analyzed.
   - Zero raw secrets displayed in findings tables or audit summaries.
5. **`dataset_loader.py`**:
   - Normalized loader for synthetic JSONL fixtures, generic CSVs, and the Kaggle *PII Data Detection* competition schema (`train.json`).
   - Validates offset boundaries `0 <= start < end <= len(text)`.
6. **`evaluation.py`**:
   - Computes True Positives, False Positives, False Negatives, Precision, Recall, and F1 per entity type and micro/macro overall.
   - Exact-span matching policy `[start, end)` by default.
   - Safe table formatter excluding raw PII.

---

## 2. Project Directory Structure

```
ai-data-leak-guardian/
├── .streamlit/
│   └── config.toml               # Streamlit theme & headless server configuration
├── app.py                        # Unified entrypoint (CLI demo, benchmark, web launch)
├── config.py                     # Centralized regex patterns, entropy limits, and thresholds
├── dataset_loader.py             # Loaders for synthetic fixtures and Kaggle datasets
├── detector.py                   # PII, secret, and Shannon entropy detection engine
├── evaluation.py                 # Benchmark evaluation engine (Precision, Recall, F1)
├── frontend.py                   # Streamlit security dashboard frontend
├── models.py                     # Pydantic data models for findings, risk, and metrics
├── redactor.py                   # Reversible redaction engine & in-memory session vault
├── requirements.txt              # Pinned core dependencies (Pydantic, Pytest, spaCy, Streamlit)
├── risk.py                       # Deterministic 4-tier exposure risk classifier
├── .gitignore                    # Git exclusions for environments, caches, datasets, keys
├── README.md                     # Comprehensive project documentation
├── datasets/
│   ├── README.md                 # Dataset specifications and Kaggle download instructions
│   ├── raw/                      # Downloaded source datasets (git-ignored)
│   └── processed/                # Normalized dataset artifacts (git-ignored)
├── fixtures/
│   ├── synthetic_pii.jsonl       # Deterministic synthetic PII benchmark data (10 records)
│   └── synthetic_secrets.jsonl   # Deterministic synthetic secret benchmark data (8 records)
├── models/
│   ├── README.md                 # Model artifact instructions
│   └── pii_ner/                  # Trained CPU-friendly spaCy English NER model
│       ├── config.cfg            # Model architecture configuration
│       ├── manifest.json         # Training provenance and audit manifest
│       ├── evaluation_report.json# 3-mode benchmark performance metrics
│       ├── meta.json             # spaCy metadata
│       ├── tokenizer             # Tokenizer configuration
│       └── ner/                  # Neural network weights
├── tests/
│   ├── test_dataset_loader.py    # Tests for loaders, Kaggle adapter, schema errors
│   ├── test_detector.py          # Unit tests for PII, secrets, entropy, offsets
│   ├── test_evaluation.py        # Tests for TP/FP/FN, F1 math, benchmark runs
│   ├── test_frontend.py          # Streamlit integration tests (AppTest suite)
│   ├── test_hybrid_detector.py   # Conflict resolution, precedence, ML fallback
│   ├── test_redactor.py          # Tests for masking, restoration, collisions, vault
│   ├── test_risk.py              # Tests for 4 risk tiers and secret priority
│   └── test_training_pipeline.py # Tests for token alignment, DocBin, and training
└── training/
    ├── README.md                 # Training pipeline documentation
    ├── prepare_data.py           # Kaggle BIO token to character span converter
    ├── train_model.py            # CPU spaCy NER trainer with manifest generation
    ├── evaluate_model.py         # Comparative evaluation: ML vs Rules vs Hybrid
    └── predict.py                # Standalone inference module with fallback
```

---

## 3. Setup Instructions (Windows & Antigravity IDE)

### Prerequisites
- Python 3.11+ (Tested on Python 3.13.14)
- Git

### Virtual Environment Setup
Open PowerShell in the project root directory:

```powershell
# 1. Create a dedicated virtual environment
python -m venv .venv

# 2. Activate the virtual environment
.\.venv\Scripts\Activate.ps1
# If PowerShell script execution is restricted, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# 3. Upgrade pip and install core dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## 4. Frontend Web Dashboard

The web dashboard is an interactive, security-focused control center built with Streamlit.

### Launching the Dashboard

Run either of the following commands from your activated virtual environment:

```powershell
# Primary launch command
streamlit run app.py

# Alternative entrypoint
python app.py --web
```

Open your browser to `http://localhost:8501`.

### Dashboard Architecture & UI Layout

1. **Header & Verified System Status**:
   - Title: **AI Data Leak Guardian**
   - Subtitle: *“Inspect locally. Redact intelligently. Restore safely.”*
   - Status badges: Dynamic verification of Backend readiness, Rules engine status, ML model availability (`Hybrid: spaCy NER` or `Rules-Only Fallback`), active vault key count, and isolated session UUID.
2. **Security Overview Metrics**:
   - Four real-time metric cards: Total Findings, Exposure Risk Level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), Credentials / Secrets count, and Detection Mode.
3. **Input Inspection Workspace**:
   - Synthetic preset loader: Pre-configured mock data for quick testing without real credentials.
   - Text area for pasting prompts, scripts, connection strings, or configuration snippets.
   - Stale input suppression: Immediately warns if input text was modified after an analysis and withholds previous findings until re-analyzed.
   - Interactive actions: `Analyze & Redact` (Primary), `Clear Analysis`, `Reset Session & Vault`, and `Refresh Status`.
4. **Detection Results**:
   - Structured findings table showing Entity Type, Risk Tier, Detection Method (`regex:*`, `spacy:en_ner:*`, `heuristic:shannon_entropy`), Character Offsets `[start, end)`, Span Length, and Safe Audit Descriptions.
   - **Zero Raw Secrets**: Raw sensitive strings are never rendered in the findings table.
5. **Risk Assessment & Audit Rationale**:
   - Deterministic risk banner with color, bold text, and visual severity markers.
   - Explainable bulleted rationales derived from the backend risk engine.
   - Hackathon prototype disclaimer.
6. **Sanitized Prompt**:
   - Masked text containing typed placeholders (`[EMAIL_1]`, `[API_KEY_1]`).
   - One-click copy via code block and `Download Sanitized Prompt` button.
   - Clear security explanation that sanitized text is safe for downstream AI forwarding.
7. **Simulated AI Response & Local Restoration**:
   - `Auto-Generate Response Template`: Constructs a synthetic AI response citing active session placeholders.
   - `Inject Unknown Placeholder`: Injects foreign tokens (e.g. `[FOREIGN_KEY_99]`) to verify untouched preservation.
   - `Restore Response Locally`: Client-side substitution restoring placeholders strictly from in-memory vault.
   - Clear categorization of Restored Tokens vs Unknown/Untouched Tokens.
   - `Purge Vault Mappings`: Instantly wipes in-memory mappings.
8. **Dataset & Model Evaluation**:
   - **Verified Benchmark Report**: Reads actual evaluation metrics from `models/pii_ner/evaluation_report.json` comparing Mode 1 (ML Alone), Mode 2 (Rules Alone), and Mode 3 (Hybrid Combined) with per-entity breakdown.
   - **Live Fixture Evaluation**: On-demand live evaluation against `fixtures/synthetic_pii.jsonl` and `fixtures/synthetic_secrets.jsonl`.
9. **Safe Session Activity Log**:
   - In-memory audit trail documenting timestamps, actions, risk levels, entity category counts, and action statuses.
   - Strictly safe metadata: zero raw input text or secrets recorded.

### Synthetic Demo Workflow

To test the application end-to-end:
1. Select **"Preset 1: Full Incident (PII + DB URL + API Key)"** from the preset dropdown and click **"Load Preset"**.
2. Click **"Analyze & Redact"**. Observe:
   - Risk Level updates to **CRITICAL**.
   - Findings table identifies the email, phone, database URI, and API key with exact offsets.
   - Sanitized prompt displays with `[EMAIL_1]`, `[PHONE_1]`, `[DB_CREDENTIAL_1]`, `[API_KEY_1]`.
3. Scroll to **Simulated AI Response & Local Restoration**, click **"Auto-Generate Response Template"**.
4. Click **"Restore Response Locally"**. Observe the original sensitive values restored locally inside the session vault.
5. Click **"Purge Vault Mappings"** or **"Reset Session & Vault"** to verify that memory mappings are purged cleanly.

---

## 5. Verification and Testing

### Running Automated Test Suite
The test suite includes 111 comprehensive unit, integration, and frontend tests running 100% offline:

```powershell
# Run the complete test suite
python -m pytest -v
```

Test coverage includes:
- `tests/test_detector.py`: PII regex, secret regex, Shannon entropy heuristics, punctuation trimming, offset bounds.
- `tests/test_redactor.py`: Masking, reverse substitution, collision avoidance, adjacent spans, session isolation, vault purging.
- `tests/test_risk.py`: 4 risk tiers, credential priority, multiple medium PII aggregation.
- `tests/test_dataset_loader.py`: JSONL loaders, CSV loaders, Kaggle schema parser, span validation.
- `tests/test_evaluation.py`: Exact-span matching, partial-span matching, zero-division safety, report formatting.
- `tests/test_hybrid_detector.py`: spaCy NER integration, precedence rules, equal-severity arbitration, rules-only fallback.
- `tests/test_training_pipeline.py`: BIO alignment, DocBin serialization, CPU training loop, manifest generation.
- `tests/test_frontend.py`: Streamlit `AppTest` suite verifying startup, preset loading, backend execution, safe findings rendering, risk matching, restoration, session clearing, stale suppression, and error handling.
- `tests/test_api_server.py`: FastAPI gateway integration suite verifying all 7 endpoints (`/api/status`, `/api/analyze`, `/api/restore`, `/api/session/reset`, `/api/presets`, `/api/evaluation/metrics`, `/api/evaluation/benchmark`, and static SPA asset serving).

All **121 automated Python tests** pass deterministically.
All **7 Vitest frontend integration tests** pass deterministically (**128 total automated tests**).

### Running Automated Tests
```powershell
# Run complete Python test suite
.venv\Scripts\python -m pytest tests/

# Run complete React frontend test suite
cd frontend && npm test
```

### CLI Pipeline Demonstration
```powershell
python app.py --demo
```

### Synthetic Benchmark Evaluation
```powershell
python app.py --benchmark
```

---

## 6. Security Architecture & Limitations

### In-Memory Vault Design
- **Zero Disk Footprint**: Original sensitive values are stored strictly inside private dictionary instances (`self._vault`) bound to a session UUID.
- **Ephemeral Lifecycle**: Calling `session.clear()` immediately purges mapping tables. Mappings are never written to disk, databases, or logs.
- **Zero External AI Calls**: The application makes zero automated network requests to OpenAI, Anthropic, or external cloud providers.
- **Client-Side Decoding**: Restored text is treated strictly as plain string data in RAM and is never executed or evaluated.

### Detection Heuristic Limitations
- **Regex Boundaries**: Regular expressions cannot identify every international name variant or unconventional national ID format without false positives.
- **Shannon Entropy Limits**: Identifies random-looking strings ($H \ge 3.6$), but low-entropy passwords (e.g. `password123`) require pattern matching.
- **Hackathon Boundary**: AI Data Leak Guardian is a privacy-enhancing local prototype built for the IBM Z Hackathon. It is not an enterprise Hardware Security Module (HSM) or certified Data Loss Prevention (DLP) appliance.

---

## 7. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy restriction | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` |
| `Port 8000 or 5173 is already in use` | Another service is using the port | Run `python server.py --port 8080` and adjust Vite proxy or use production mode |
| `ML model artifacts not found at models/pii_ner` | Model directory was moved or deleted | The application automatically falls back to **Rules-Only mode**. To re-train, run `python training/train_model.py` |
| `Unable to connect to Data Leak Guardian backend` in React UI | `server.py` is not running | Ensure `python server.py` is running on port 8000 |

---

## 8. IBM LinuxONE Deployment & Compatibility Status

- **Target Architecture**: Ubuntu 24.04 LTS on s390x (IBM LinuxONE, 3 vCPUs, 8 GB RAM).
- **Current Status**: **Fully Verified Locally & Ready for s390x VM Deployment**.
- **Optimization Measures**:
  - Pure Python CPU-optimized execution with zero GPU requirements.
  - Endian-neutral character span offsets using Unicode code points.
  - Single-port static asset serving via FastAPI: the compiled React bundle (`frontend/dist`) runs with **Python only**, requiring zero Node.js runtime on LinuxONE.
  - Hybrid detector cached in memory once at startup, avoiding per-request spaCy reloading.
  - Graceful rules-only fallback if ML model artifacts are omitted.

---

## 9. Hackathon Milestones

1. **Prompt 1: Core Backend Engine** (Status: Complete):
   - Modular detector, risk assessment, reversible redactor, evaluation pipeline, and automated test suite.
2. **Prompt 2: Backend Integrity & Hardening** (Status: Complete):
   - Regression fixes, audit detail, deduplication, and test suite expansion.
3. **Prompt 3: ML Training & Hybrid Integration** (Status: Complete):
   - Kaggle PII preprocessing pipeline, CPU-trainable spaCy NER model, deterministic conflict resolution, artifact manifest, and 99 passing tests.
4. **Prompt 4: Streamlit Frontend** (Status: Complete):
   - Interactive security dashboard, verified status area, synthetic presets, stale finding suppression, sanitized prompt copy/download, and 12 Streamlit AppTests (111 tests passing).
5. **Prompt 5: React 18 + Vite Frontend Redesign & FastAPI Gateway** (Status: Complete):
   - Complete IntelliCluster-inspired React 18 + TypeScript + Tailwind CSS redesign.
   - FastAPI gateway (`server.py`) exposing 7 validated REST endpoints.
   - Movable dashboard widget grid with keyboard accessibility.
   - Dual-mode serving for IBM LinuxONE production without Node.js.
   - 121 Python pytest tests passing + 7 Vitest frontend tests passing (128 total automated tests).
6. **Prompt 6: IBM LinuxONE Deployment** (Next Stage):
   - Deployment and validation on an Ubuntu s390x VM on IBM LinuxONE.
