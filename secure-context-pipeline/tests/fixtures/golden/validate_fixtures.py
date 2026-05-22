#!/usr/bin/env python3
"""
validate_fixtures.py — Golden Dataset Fixture Validator
Secure Context Pipeline — Test Fixture Specification

Usage:
    python validate_fixtures.py [--fixture-dir PATH]

Exit code 0 if all fixtures pass, exit code 1 if any fail.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# SSNs explicitly allowed as synthetic test values even if not starting with 9.
# These are documented in Rule G-001 as having no known real-person mapping.
ALLOWED_TEST_SSNS = {
    "543678901",   # 543-67-8901
    "987123456",   # 987-12-3456
}

TOKEN_PATTERN = re.compile(r"\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]")


def normalize_ssn(raw: str) -> str:
    """Strip dashes and spaces from an SSN string for format-agnostic comparison."""
    return raw.replace("-", "").replace(" ", "")


def validate_annotation(fixture_text: str, annotation: dict, annotation_path: str) -> list:
    """
    Validate a single annotation dict against its fixture text.
    Returns a list of error strings (empty list means PASS).
    """
    errors = []

    # Rule G-002: Required top-level fields
    required_fields = {"fixture_id", "fixture_file", "description", "entities"}
    missing = required_fields - set(annotation.keys())
    if missing:
        errors.append(f"[G-002] Missing required annotation fields: {sorted(missing)}")

    entities = annotation.get("entities", [])
    if not isinstance(entities, list):
        errors.append("[G-002] 'entities' field must be a list")
        return errors  # Cannot continue checking entities

    for i, entity in enumerate(entities):
        label = f"Entity[{i}] ({entity.get('entity_type', '?')} '{entity.get('original_value', '?')}')"

        # Rule G-002: Required entity fields
        required_entity_fields = {"entity_type", "original_value", "start_char", "end_char", "expected_confidence_min"}
        missing_entity = required_entity_fields - set(entity.keys())
        if missing_entity:
            errors.append(f"[G-002] {label}: Missing required entity fields: {sorted(missing_entity)}")
            continue

        start = entity["start_char"]
        end = entity["end_char"]
        expected_value = entity["original_value"]

        # Rule G-003: Exact span match
        if start < 0 or end > len(fixture_text) or start >= end:
            errors.append(
                f"[G-003] {label}: Span [{start}:{end}] is out of bounds "
                f"(fixture length={len(fixture_text)})"
            )
        else:
            extracted = fixture_text[start:end]
            if extracted != expected_value:
                errors.append(
                    f"[G-003] {label}: Span mismatch. "
                    f"Expected '{expected_value}' ({len(expected_value)} chars), "
                    f"got '{extracted}' ({len(extracted)} chars) "
                    f"at [{start}:{end}]"
                )

        # Rule G-001: SSN must start with 9 or be in the allowed list
        if entity.get("entity_type") == "PII_SSN":
            ssn_normalized = normalize_ssn(expected_value)
            if not ssn_normalized.startswith("9") and ssn_normalized not in ALLOWED_TEST_SSNS:
                errors.append(
                    f"[G-001] {label}: SSN '{expected_value}' may not be synthetic. "
                    f"Use 9XX-XX-XXXX format or add to ALLOWED_TEST_SSNS."
                )

        # Rule G-005: No entity spanning a newline
        if "\n" in expected_value:
            errors.append(
                f"[G-005] {label}: Entity value contains a newline character. "
                f"Split into two entities or reformat the fixture."
            )

    return errors


def find_fixture_pairs(fixture_dir: Path) -> list:
    """
    For each .json annotation file, find the corresponding .txt file (if any).
    Returns list of (json_path, txt_path_or_None) pairs.
    F-007 style fixtures have no .txt companion — txt_path will be None.
    """
    pairs = []
    for json_path in sorted(fixture_dir.glob("*.json")):
        txt_path = json_path.with_suffix(".txt")
        if txt_path.exists():
            pairs.append((json_path, txt_path))
        else:
            pairs.append((json_path, None))
    return pairs


def run_validation(fixture_dir: Path) -> bool:
    """
    Run validation on all fixtures in fixture_dir.
    Returns True if all pass, False if any fail.
    """
    pairs = find_fixture_pairs(fixture_dir)

    if not pairs:
        print(f"No .json annotation files found in {fixture_dir}")
        return False

    all_passed = True

    for json_path, txt_path in pairs:
        print(f"\n{'=' * 60}")
        print(f"Fixture: {json_path.name}")

        try:
            with open(json_path, encoding="utf-8") as f:
                annotation = json.load(f)
        except json.JSONDecodeError as e:
            print(f"  FAIL  [JSON parse error]: {e}")
            all_passed = False
            continue

        if txt_path is not None:
            try:
                with open(txt_path, encoding="utf-8") as f:
                    fixture_text = f.read()
            except OSError as e:
                print(f"  FAIL  [Cannot read .txt file]: {e}")
                all_passed = False
                continue
        else:
            fixture_text = ""
            entities = annotation.get("entities", [])
            if entities:
                print(
                    f"  WARN  No .txt companion file found but annotation has {len(entities)} entities. "
                    f"Span checks will fail. Is this a JSON-only fixture (like F-007)?"
                )

        errors = validate_annotation(fixture_text, annotation, str(json_path))

        if errors:
            print(f"  FAIL  ({len(errors)} error(s)):")
            for err in errors:
                print(f"    - {err}")
            all_passed = False
        else:
            entity_count = len(annotation.get("entities", []))
            print(f"  PASS  ({entity_count} entities validated)")

    print(f"\n{'=' * 60}")
    if all_passed:
        print("ALL FIXTURES PASSED")
    else:
        print("ONE OR MORE FIXTURES FAILED — see errors above")

    return all_passed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate golden dataset fixtures against their JSON annotations."
    )
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=Path("tests/fixtures/golden"),
        help="Directory containing fixture .txt and .json files (default: tests/fixtures/golden)",
    )
    args = parser.parse_args()

    fixture_dir = args.fixture_dir
    if not fixture_dir.is_dir():
        print(f"ERROR: Fixture directory does not exist: {fixture_dir}")
        sys.exit(1)

    passed = run_validation(fixture_dir)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
