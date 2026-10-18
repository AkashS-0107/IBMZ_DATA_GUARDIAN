"""Entry-point for AI Data Leak Guardian.

Supports:
1. Streamlit interactive security dashboard:
   streamlit run app.py
2. Command-line pipeline demonstration:
   python app.py --demo
3. Benchmark evaluation across synthetic fixtures:
   python app.py --benchmark
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Detect if running within a Streamlit server instance
try:
    from streamlit.runtime import exists as _st_exists
    _RUNNING_IN_STREAMLIT = _st_exists()
except Exception:
    _RUNNING_IN_STREAMLIT = False

if _RUNNING_IN_STREAMLIT:
    from frontend import render_app
    render_app()
else:
    from dataset_loader import load_synthetic_jsonl
    from detector import Detector
    from evaluation import Evaluator, format_evaluation_report
    from redactor import RedactionSession
    from risk import assess_risk

    def run_pipeline_demo() -> None:
        """Demonstrate end-to-end backend pipeline: detect -> assess -> redact -> restore."""
        print("=" * 72)
        print("AI DATA LEAK GUARDIAN - BACKEND DEMO PIPELINE")
        print("=" * 72)

        sample_input = (
            "Hello, my name is Johnathan Doe. Please contact me at johnathan.doe@company.org "
            "or call +1-800-555-0199. For deployment, use password='SuperSecretPassword123' "
            "and connect to postgresql://admin:prodPass99@db.internal:5432/core_db."
        )

        print("\n[1] ORIGINAL INPUT (In-Memory Processing Only):")
        print(sample_input)

        # 1. Detection
        detector = Detector()
        findings = detector.detect(sample_input)
        print(f"\n[2] DETECTED FINDINGS ({len(findings)} non-overlapping matches):")
        for idx, f in enumerate(findings, start=1):
            print(f"  {idx}. Type: {f.entity_type.value:<14} Span: [{f.start:>2}, {f.end:>3}) "
                  f"Severity: {f.severity.value:<8} Rule: {f.rule_id}")

        # 2. Risk Assessment
        risk = assess_risk(findings)
        print(f"\n[3] RISK ASSESSMENT:")
        print(f"  Overall Risk Level: {risk.risk_level.value}")
        print("  Safe Audit Reasons:")
        for reason in risk.reasons:
            print(f"    - {reason}")

        # 3. Redaction
        session = RedactionSession()
        redaction = session.redact(sample_input, findings)
        print(f"\n[4] REDACTED TEXT (Safe to forward to External AI):")
        print(redaction.masked_text)

        # 4. Simulated AI Response with placeholders
        simulated_ai_response = (
            f"Thank you for contacting us. We have registered your inquiry for [EMAIL_1] "
            f"and scheduled an update via [PHONE_1]. Your database service [DB_CREDENTIAL_1] "
            f"has been verified."
        )
        print(f"\n[5] SIMULATED AI RESPONSE (Received with Placeholders):")
        print(simulated_ai_response)

        # 5. Local Restoration
        restored_text = session.restore(simulated_ai_response)
        print(f"\n[6] LOCALLY RESTORED RESPONSE (Decoded in session vault):")
        print(restored_text)

        # 6. Session Isolation & Vault Purge
        session.clear()
        print(f"\n[7] SESSION PURGE:")
        print(f"  Active vault keys after clear(): {session.active_placeholder_count}")
        print("=" * 72)
        print("\n[TIP] Launch the graphical security dashboard by running:")
        print("    streamlit run app.py\n")

    def run_benchmark() -> None:
        """Run reproducible benchmark against synthetic test fixtures."""
        fixtures_dir = Path(__file__).parent / "fixtures"
        pii_path = fixtures_dir / "synthetic_pii.jsonl"
        secrets_path = fixtures_dir / "synthetic_secrets.jsonl"

        if not pii_path.is_file() or not secrets_path.is_file():
            print("Error: Synthetic fixture files not found in fixtures/ directory.", file=sys.stderr)
            sys.exit(1)

        records = load_synthetic_jsonl(pii_path) + load_synthetic_jsonl(secrets_path)
        evaluator = Evaluator()
        report = evaluator.evaluate_dataset(records)
        print(format_evaluation_report(report))

    def main() -> None:
        parser = argparse.ArgumentParser(
            description="AI Data Leak Guardian - Backend Engine & Dashboard"
        )
        parser.add_argument(
            "--demo", action="store_true", default=False,
            help="Run end-to-end detection, redaction, and restoration demonstration."
        )
        parser.add_argument(
            "--benchmark", action="store_true",
            help="Run benchmark evaluation across synthetic fixtures."
        )
        parser.add_argument(
            "--web", action="store_true",
            help="Launch the interactive Streamlit security dashboard."
        )

        args = parser.parse_args()

        if args.web:
            import subprocess
            subprocess.run(["streamlit", "run", str(Path(__file__).resolve())])
        elif args.benchmark:
            run_benchmark()
        else:
            run_pipeline_demo()

    if __name__ == "__main__":
        main()
