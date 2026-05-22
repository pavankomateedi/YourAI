#!/usr/bin/env python3
"""Detection recall/precision benchmark against the golden dataset.

Recall is the gatekeeping metric for the pipeline's privacy guarantee: an entity
the detector misses is never obfuscated and the leak gate cannot vault it. This
script runs the real detector over every annotated golden fixture, matches
detections against ground truth, and reports per-entity-type recall plus a coarse
precision. Exits non-zero if recall for any required type falls below the
threshold, so it can gate CI.

    python scripts/recall_benchmark.py --min-recall 0.90
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "golden"


def _spans_overlap(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end


async def run(min_recall: float) -> int:
    from secure_context_pipeline.detection.detector import PIIDetector

    detector = PIIDetector()

    gt_total: dict[str, int] = defaultdict(int)
    gt_found: dict[str, int] = defaultdict(int)
    detected_total: dict[str, int] = defaultdict(int)
    detected_matched: dict[str, int] = defaultdict(int)

    fixtures = sorted(GOLDEN_DIR.glob("F-*.json"))
    for jpath in fixtures:
        annotation = json.loads(jpath.read_text(encoding="utf-8"))
        entities = annotation.get("entities") or []
        if not entities:
            continue
        tpath = jpath.with_suffix(".txt")
        if not tpath.exists():
            continue
        text = tpath.read_text(encoding="utf-8")
        detected = await detector.detect(text)

        for d in detected:
            detected_total[d.entity_type] += 1

        for gt in entities:
            etype = gt["entity_type"]
            gt_total[etype] += 1
            value, gs, ge = gt["original_value"], gt["start_char"], gt["end_char"]
            hit = next(
                (
                    d for d in detected
                    if d.entity_type == etype
                    and (value in d.original_value or d.original_value in value)
                    and _spans_overlap(gs, ge, d.start, d.end)
                ),
                None,
            )
            if hit:
                gt_found[etype] += 1
                detected_matched[hit.entity_type] += 1

    print(f"{'ENTITY TYPE':<20} {'RECALL':>8} {'(found/total)':>14} {'~PRECISION':>11}")
    print("-" * 56)
    all_types = sorted(set(gt_total) | set(detected_total))
    failing = []
    for etype in all_types:
        total = gt_total.get(etype, 0)
        found = gt_found.get(etype, 0)
        recall = found / total if total else 1.0
        dtot = detected_total.get(etype, 0)
        prec = detected_matched.get(etype, 0) / dtot if dtot else 1.0
        flag = ""
        if total and recall < min_recall:
            failing.append(etype)
            flag = "  <-- BELOW THRESHOLD"
        print(f"{etype:<20} {recall:>7.0%} {f'({found}/{total})':>14} {prec:>10.0%}{flag}")

    overall_total = sum(gt_total.values())
    overall_found = sum(gt_found.values())
    overall = overall_found / overall_total if overall_total else 1.0
    print("-" * 56)
    print(f"{'OVERALL RECALL':<20} {overall:>7.0%} {f'({overall_found}/{overall_total})':>14}")
    print(f"\nThreshold: {min_recall:.0%}. " + ("PASS" if not failing else f"FAIL: {failing}"))
    return 0 if not failing else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Detection recall benchmark over golden fixtures.")
    parser.add_argument("--min-recall", type=float, default=0.80)
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.min_recall)))


if __name__ == "__main__":
    main()
