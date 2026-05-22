#!/usr/bin/env python3
"""Generate golden-dataset annotation JSON with exact character offsets.

The harness matches entities by ``original_value`` (not by offset), but
``validate_fixtures.py`` enforces byte-exact spans. Rather than hand-counting
offsets, this helper locates each annotated value in its fixture text — tracking
repeated values so each occurrence gets a distinct span — and writes the JSON.

Run from the golden directory:  python _build_annotations.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent

# (entity_type, original_value, expected_confidence_min) in document order.
# Repeated values are resolved to successive occurrences automatically.
SPECS: dict[str, dict] = {
    "F-001_medical_record_comprehensive": {
        "description": "Comprehensive medical record — all 14 entity types",
        "entities": [
            ("PII_NAME", "Dr. Eleanor Hartwell", 0.85),
            ("PII_SSN", "543-67-8901", 0.95),
            ("PII_DOB", "March 14, 1972", 0.90),
            ("PII_ADDRESS", "2847 Lakeview Drive, Austin, TX 78701", 0.85),
            ("PII_EMAIL", "eleanor.hartwell@example-clinic.org", 0.99),
            ("PII_PHONE", "(512) 555-0147", 0.95),
            ("PHI_MRN", "MRN-7293847", 0.80),
            ("PHI_INSURANCE_ID", "BCBS-TX-0042-8837291", 0.80),
            ("PHI_DIAGNOSIS", "Type 2 Diabetes Mellitus", 0.85),
            ("PHI_MEDICATION", "Metformin 500mg", 0.85),
            ("PHI_LAB_RESULT", "HbA1c: 8.2%", 0.80),
            ("FIN_ACCOUNT", "4532-1234-5678-9012", 0.90),
            ("FIN_TAX_ID", "EIN: 74-1234567", 0.90),
            ("LEGAL_CLIENT", "Martinez Family Trust", 0.75),
        ],
    },
    "F-002_legal_brief_privilege": {
        "description": "Privileged legal memo with client identity and case strategy",
        "entities": [
            ("PII_NAME", "Marcus R. Webb", 0.85),
            ("LEGAL_CLIENT", "Martinez Family Trust", 0.75),
            ("PII_NAME", "Priya Okonkwo", 0.85),
            ("PII_SSN", "987-12-3456", 0.95),
            ("LEGAL_STRATEGY", "settle at no less than $2.4 million", 0.70),
            ("PII_EMAIL", "priya.okonkwo@martinez-trust.example.com", 0.99),
            ("PII_PHONE", "(415) 555-0293", 0.95),
            ("LEGAL_CLIENT", "Martinez Family Trust", 0.75),
        ],
    },
    "F-003_financial_disclosure": {
        "description": "Financial disclosure — multiple accounts, DOB, tax ID, repeated account refs",
        "entities": [
            ("PII_NAME", "Raj Patel", 0.85),
            ("PII_DOB", "September 7, 1968", 0.90),
            ("FIN_TAX_ID", "EIN): 23-4567890", 0.85),
            ("FIN_ACCOUNT", "4111-2222-3333-4444", 0.90),
            ("FIN_ACCOUNT", "SAVINGS-77-8812345", 0.80),
            ("FIN_ACCOUNT", "4111-2222-3333-4444", 0.90),
            ("FIN_ACCOUNT", "4111-2222-3333-4444", 0.90),
            ("PII_EMAIL", "raj.patel.advisor@example-finance.com", 0.99),
            ("PII_PHONE", "(713) 555-0384", 0.95),
            ("PII_ADDRESS", "9102 Westwood Boulevard, Houston, TX 77001", 0.85),
        ],
        "extra": {
            "idempotency_assertions": [
                {
                    "entities_with_same_value": ["4111-2222-3333-4444"],
                    "expected_behavior": "all_occurrences_map_to_same_token",
                }
            ]
        },
    },
    "F-004_clean_medical_guidance": {
        "description": "No PII/PHI — negative detection test. General medical guidance only.",
        "entities": [],
        "extra": {
            "expected_behavior": {
                "detection": "empty_entity_list",
                "obfuscation": "text_unchanged",
                "pipeline": "completes_without_error",
            }
        },
    },
    "F-005_idempotency_stress": {
        "description": "Same name + SSN repeated 7 times — idempotency test",
        "entities": [
            spec
            for _ in range(7)
            for spec in (
                ("PII_NAME", "Dr. Eleanor Hartwell", 0.85),
                ("PII_SSN", "543-67-8901", 0.95),
            )
        ],
        "extra": {
            "idempotency_assertions": [
                {"entities_with_same_value": ["Dr. Eleanor Hartwell"], "expected_token_count": 1},
                {"entities_with_same_value": ["543-67-8901"], "expected_token_count": 1},
            ]
        },
    },
    "F-006_low_confidence_entity": {
        "description": "Low-confidence ambiguous first name 'John' — must trigger redaction",
        "entities": [
            ("PII_NAME", "John", 0.0),
            ("PHI_MEDICATION", "Metformin 500mg", 0.85),
            ("PHI_MRN", "MRN-7293847", 0.80),
            ("PII_NAME", "Dr. Eleanor Hartwell", 0.85),
        ],
        "extra": {
            "redaction_assertions": [
                {"entity_value": "John", "expected_output": "[REDACTED]", "reason": "confidence_below_threshold"}
            ]
        },
        "confidence_max": {"John": 0.60},
    },
    "F-008_multi_format_ssn": {
        "description": "SSN in 4 format variants: dashes, spaces, no separator, embedded",
        "entities": [
            ("PII_SSN", "912-34-5678", 0.95),
            ("PII_SSN", "923 45 6789", 0.90),
            ("PII_SSN", "934567890", 0.75),
            ("PII_SSN", "945-67-8901", 0.95),
        ],
    },
    "F-009_adjacent_entities": {
        "description": "Pairs of PII entities within 3 chars — must not merge into one span",
        "entities": [
            ("PII_NAME", "John Smith", 0.85),
            ("PII_SSN", "943-67-8901", 0.95),
            ("PII_NAME", "Priya Okonkwo", 0.85),
            ("PII_EMAIL", "priya.okonkwo@example.org", 0.99),
            ("PII_NAME", "Dr. Amos Vega", 0.85),
            ("PII_NAME", "Dr. Sara Lund", 0.85),
        ],
    },
}


def build(stem: str, spec: dict) -> None:
    text = (HERE / f"{stem}.txt").read_text(encoding="utf-8")
    cursor: dict[str, int] = {}
    entities = []
    conf_max = spec.get("confidence_max", {})
    for etype, value, conf in spec["entities"]:
        start = text.find(value, cursor.get(value, 0))
        if start < 0:
            raise SystemExit(f"{stem}: value not found: {value!r}")
        end = start + len(value)
        cursor[value] = start + 1  # next occurrence starts after this one
        entry = {
            "entity_type": etype,
            "original_value": value,
            "start_char": start,
            "end_char": end,
            "expected_confidence_min": conf,
        }
        if value in conf_max:
            entry["expected_confidence_max"] = conf_max[value]
        entities.append(entry)

    annotation = {
        "fixture_id": stem.split("_")[0],
        "fixture_file": f"tests/fixtures/golden/{stem}.txt",
        "description": spec["description"],
        "entities": entities,
    }
    annotation.update(spec.get("extra", {}))
    (HERE / f"{stem}.json").write_text(json.dumps(annotation, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {stem}.json ({len(entities)} entities)")


if __name__ == "__main__":
    for stem, spec in SPECS.items():
        build(stem, spec)
