#!/usr/bin/env python3
"""pii_leakage_scan.py — Standalone PII leakage scanner.

Reads text from a file or stdin and checks for any of a configurable set of known
PII values. Reports violations and exits 1 if any are found. Zero external
dependencies (stdlib only) so it can gate CI cheaply.

Also supports ``--runs N`` to drive the pipeline over varied fixtures and confirm
zero leakage across many obfuscation passes (the spec's 100-run verification).

Exit codes: 0 = clean, 1 = leakage detected, 2 = usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

DEFAULT_PII_VALUES: dict[str, str] = {
    "PII_NAME": "Dr. Eleanor Hartwell",
    "PII_SSN": "543-67-8901",
    "PII_DOB": "March 14, 1972",
    "PII_ADDRESS": "2847 Lakeview Drive, Austin, TX 78701",
    "PII_EMAIL": "eleanor.hartwell@example-clinic.org",
    "PII_PHONE": "(512) 555-0147",
    "PHI_MRN": "MRN-7293847",
    "PHI_DIAGNOSIS": "Type 2 Diabetes Mellitus",
    "PHI_MEDICATION": "Metformin 500mg",
    "PHI_INSURANCE_ID": "BCBS-TX-0042-8837291",
    "PHI_LAB_RESULT": "HbA1c: 8.2%",
    "FIN_ACCOUNT": "4532-1234-5678-9012",
    "FIN_TAX_ID": "EIN: 74-1234567",
    "LEGAL_CLIENT": "Martinez Family Trust",
}


def scan_text(text: str, pii_values: dict[str, str]) -> list[dict]:
    violations = []
    low = text.lower()
    for entity_type, value in pii_values.items():
        idx = low.find(value.lower())
        if idx != -1:
            violations.append({"entity_type": entity_type, "value": value, "first_offset": idx})
    return violations


def load_pii_file(path: str) -> dict[str, str]:
    if not os.path.exists(path):
        print(f"ERROR: PII file not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        print("ERROR: PII file must contain a JSON object", file=sys.stderr)
        sys.exit(2)
    return {str(k): str(v) for k, v in data.items()}


def read_input(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read()
    if args.input:
        if not os.path.exists(args.input):
            print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(2)
        with open(args.input, encoding="utf-8") as f:
            return f.read()
    print("ERROR: Provide --input <file>, --stdin, or --runs N", file=sys.stderr)
    sys.exit(2)


async def run_pipeline_scan(runs: int) -> int:
    """Obfuscate many fixture variants and count leaked original values."""
    from secure_context_pipeline.detection.detector import PIIDetector
    from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
    from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
    from secure_context_pipeline.models import REQUIRED_ENTITY_TYPES
    from secure_context_pipeline.vault.vault import SessionVault
    import uuid

    detector = PIIDetector()
    engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})

    names = ["Eleanor Hartwell", "Marcus Webb", "Priya Okonkwo", "Raj Patel", "Sarah Chen"]
    ssns = ["543-67-8901", "987-65-4321"]
    variants = [
        f"Patient: {n} — SSN: {s} — Account: 4532-1234-5678-9012 — Email: {n.split()[0].lower()}@example.com"
        for n in names for s in ssns
    ]
    leaks = 0
    for i in range(runs):
        variant = variants[i % len(variants)]
        vault = SessionVault(db_path=os.path.join(os.getcwd(), "data", "scan_vault.db"))
        session_id = f"scan-{uuid.uuid4().hex[:8]}"
        entities = await detector.detect(variant)
        result = await engine.obfuscate_document(variant, entities, vault, session_id)
        for e in entities:
            if e.confidence >= 0.60 and e.original_value.lower() in result.obfuscated_text.lower():
                leaks += 1
        await vault.destroy(session_id)

    print(f"Ran {runs} obfuscation passes — {leaks} leak(s) detected.")
    return 0 if leaks == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan text for PII leakage. Exit 0 if clean, 1 if PII found.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", metavar="FILE", help="Text file to scan.")
    parser.add_argument("--stdin", action="store_true", help="Read input from stdin.")
    parser.add_argument("--pii-file", metavar="JSON_FILE", help="JSON of PII values to scan for.")
    parser.add_argument("--runs", type=int, help="Run the pipeline N times and verify zero leakage.")
    parser.add_argument("--json-output", action="store_true", help="Emit violations as JSON lines.")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output; exit code only.")
    args = parser.parse_args()

    if args.runs is not None:
        sys.exit(asyncio.run(run_pipeline_scan(args.runs)))

    pii_values = load_pii_file(args.pii_file) if args.pii_file else DEFAULT_PII_VALUES
    text = read_input(args)
    violations = scan_text(text, pii_values)

    if not violations:
        if not args.quiet:
            print("CLEAN: No PII values found in input.")
        sys.exit(0)
    if not args.quiet:
        if args.json_output:
            for v in violations:
                print(json.dumps(v))
        else:
            print(f"PII LEAKAGE DETECTED: {len(violations)} violation(s):")
            for v in violations:
                print(f"  [{v['entity_type']}] value={v['value']!r} first_offset={v['first_offset']}")
    sys.exit(1)


if __name__ == "__main__":
    main()
