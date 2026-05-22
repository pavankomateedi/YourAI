"""PII/PHI Detector — hybrid rule-based + NER detection.

Architecture
------------
* **Rule-based recognizers** (regex + lexicons, see :mod:`.patterns`) provide
  high-precision detection for the 14 structured/medical/legal entity types. They
  are deterministic, fast, and dependency-free, so detection works identically in
  a minimal local venv and in the full container.
* **Named-entity recognition** supplies ``PII_NAME``. When Microsoft Presidio +
  spaCy are installed (the container path) the analyzer's ``PERSON`` results are
  used; otherwise a capitalized-name heuristic is the fallback. Either way, a
  leading honorific ("Dr.", "Ms.") is folded into the name span.

All detector work is CPU-bound, so :meth:`detect` offloads to a thread to keep the
event loop responsive (the async I/O NFR).
"""

from __future__ import annotations

import asyncio
import os
import re

from ..models import DetectedEntity
from . import patterns as P

# Lazily-initialized Presidio analyzer; None means "use the heuristic fallback".
_PRESIDIO_ANALYZER = None
_PRESIDIO_TRIED = False

# Cache for an optional scispaCy medical-NER pipeline, keyed by model name.
_SCISPACY_CACHE: dict = {}


def _load_scispacy(model: str):
    if model in _SCISPACY_CACHE:
        return _SCISPACY_CACHE[model]
    try:
        import spacy

        nlp = spacy.load(model)
    except Exception:
        nlp = None
    _SCISPACY_CACHE[model] = nlp
    return nlp


def _try_load_presidio():
    global _PRESIDIO_ANALYZER, _PRESIDIO_TRIED
    if _PRESIDIO_TRIED:
        return _PRESIDIO_ANALYZER
    _PRESIDIO_TRIED = True
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
            }
        )
        _PRESIDIO_ANALYZER = AnalyzerEngine(nlp_engine=provider.create_engine())
    except Exception:
        # spaCy/Presidio (or the model) not installed — heuristic NER will be used.
        _PRESIDIO_ANALYZER = None
    return _PRESIDIO_ANALYZER


class PIIDetector:
    """Detect and classify sensitive entities in plaintext."""

    def __init__(self, use_presidio: bool = True) -> None:
        self._analyzer = _try_load_presidio() if use_presidio else None

    async def detect(self, text: str, context_hint: str | None = None) -> list[DetectedEntity]:
        return await asyncio.to_thread(self._detect_sync, text)

    # alias used in some specs; returns the same flat entity list
    async def detect_with_spans(self, text: str) -> list[DetectedEntity]:
        return await self.detect(text)

    # ------------------------------------------------------------------
    def _detect_sync(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []

        # 1. Rule-based recognizers for the 14 structured types.
        for entity_type, regexes in P.PATTERNS.items():
            for idx, rx in enumerate(regexes):
                conf = P.PATTERN_CONFIDENCE.get((entity_type, idx), 0.80)
                for m in rx.finditer(text):
                    value = m.group(0)
                    start = m.start()
                    # Trim leading whitespace the lazy address pattern may include.
                    lead = len(value) - len(value.lstrip())
                    entities.append(
                        DetectedEntity(
                            entity_type=entity_type,
                            original_value=value[lead:],
                            start=start + lead,
                            end=m.end(),
                            confidence=conf,
                            detection_method="regex",
                        )
                    )

        # 2. Names via Presidio (PERSON) or the heuristic fallback.
        entities.extend(self._detect_names(text))

        # 3. Optional medical NER (scispaCy) to raise diagnosis/medication recall
        #    beyond the lexicon. No-op unless a scispaCy model is configured.
        entities.extend(self._detect_medical_ner(text))

        # 4. Resolve overlaps so each region carries a single best label.
        return self._resolve(entities)

    def _detect_medical_ner(self, text: str) -> list[DetectedEntity]:
        """Augment medical detection with a scispaCy model when available.

        Enabled by setting ``SCISPACY_MODEL`` (e.g. ``en_ner_bc5cdr_md``) with the
        model installed. Maps DISEASE->PHI_DIAGNOSIS and CHEMICAL->PHI_MEDICATION.
        Fully guarded: any failure leaves the lexicon-based detection untouched.
        """
        model = os.environ.get("SCISPACY_MODEL")
        if not model:
            return []
        try:
            nlp = _load_scispacy(model)
            if nlp is None:
                return []
            label_map = {"DISEASE": "PHI_DIAGNOSIS", "CHEMICAL": "PHI_MEDICATION"}
            out: list[DetectedEntity] = []
            for ent in nlp(text).ents:
                etype = label_map.get(ent.label_)
                if etype:
                    out.append(
                        DetectedEntity(etype, ent.text, ent.start_char, ent.end_char, 0.85, "scispacy")
                    )
            return out
        except Exception:  # pragma: no cover - defensive
            return []

    def _detect_names(self, text: str) -> list[DetectedEntity]:
        names: list[DetectedEntity] = []
        if self._analyzer is not None:
            try:
                results = self._analyzer.analyze(text=text, entities=["PERSON"], language="en")
                for r in results:
                    start, end = self._expand_title(text, r.start, r.end)
                    value = text[start:end]
                    if self._looks_like_name(value):
                        names.append(
                            DetectedEntity("PII_NAME", value, start, end,
                                           max(float(r.score), 0.85), "ner")
                        )
            except Exception:
                pass

        # Heuristic pass (also runs alongside Presidio; dedup handles duplicates).
        for m in P.NAME_PATTERN.finditer(text):
            start, end = self._expand_title(text, m.start(), m.end())
            value = text[start:end]
            names.append(DetectedEntity("PII_NAME", value, start, end, P.NAME_CONFIDENCE, "heuristic"))
        return names

    @staticmethod
    def _expand_title(text: str, start: int, end: int) -> tuple[int, int]:
        """Fold a leading honorific (already inside or just before the span) in."""
        prefix = text[max(0, start - 8):start]
        m = P.NAME_TITLE_PREFIX.search(prefix)
        if m:
            start = max(0, start - (len(prefix) - m.start()))
        return start, end

    @staticmethod
    def _looks_like_name(value: str) -> bool:
        # Require at least two tokens or an explicit honorific to reject stray
        # single-word PERSON hits (which are the main source of false positives).
        tokens = value.split()
        if len(tokens) >= 2:
            return True
        return bool(re.match(r"^(?:Dr|Mr|Mrs|Ms|Prof)\.?$", tokens[0])) if tokens else False

    @staticmethod
    def _resolve(entities: list[DetectedEntity]) -> list[DetectedEntity]:
        """Drop exact duplicates and spans fully contained in a longer, higher- or
        equal-priority span. Distinct adjacent entities are preserved."""
        # Sort by start asc, then by length desc so the longest at a position wins.
        ordered = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
        kept: list[DetectedEntity] = []
        for e in ordered:
            redundant = False
            for k in kept:
                # Same span and same type -> duplicate.
                if e.start == k.start and e.end == k.end and e.entity_type == k.entity_type:
                    redundant = True
                    break
                # Fully contained within an already-kept span -> drop the smaller.
                if k.start <= e.start and e.end <= k.end and (e.end - e.start) < (k.end - k.start):
                    redundant = True
                    break
            if not redundant:
                kept.append(e)
        return kept
