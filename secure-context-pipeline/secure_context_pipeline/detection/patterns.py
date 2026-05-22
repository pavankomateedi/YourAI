"""Regex patterns and lexicons shared by the detector and the Presidio recognizers.

Keeping every pattern in one module means adding a new entity type is a single,
localized change (the Extensibility NFR): add a pattern here and a confidence in
``PATTERN_CONFIDENCE`` — no change to the obfuscation, vault, or pipeline layers.

Detection notes deliberately encoded in the patterns
----------------------------------------------------
* ``FIN_ACCOUNT`` matches card-style grouped numbers only, so an account label like
  ``SAVINGS-77-8812345`` is *not* swept up — this keeps idempotency tests precise.
* Medical patterns require a discriminating qualifier (a dosage after a drug, a
  value after a lab, "Mellitus" after a diabetes diagnosis) so generic prose such
  as "patients taking Metformin" or "annual HbA1c testing" does not false-fire.
"""

from __future__ import annotations

import re

# --- Lexicons -------------------------------------------------------------
# Conservative on purpose: only forms specific enough to avoid matching general
# medical prose. Extend as needed; each addition is independent of the engine.
DIAGNOSIS_LEXICON = [
    r"Type\s+2\s+Diabetes\s+Mellitus",
    r"Type\s+1\s+Diabetes\s+Mellitus",
    r"Major\s+Depressive\s+Disorder",
    r"Chronic\s+Kidney\s+Disease",
    r"Coronary\s+Artery\s+Disease",
    r"Congestive\s+Heart\s+Failure",
    r"Hypertensive\s+Heart\s+Disease",
]
MEDICATION_NAMES = [
    "Metformin", "Lisinopril", "Atorvastatin", "Amlodipine", "Losartan",
    "Omeprazole", "Levothyroxine", "Metoprolol", "Gabapentin", "Sertraline",
    "Insulin", "Hydrochlorothiazide", "Simvastatin", "Albuterol", "Warfarin",
]
LAB_NAMES = [
    "HbA1c", "Creatinine", "Glucose", "Cholesterol", "LDL", "HDL",
    "Triglycerides", "TSH", "WBC", "Hemoglobin", "Potassium", "Sodium",
]
INSURANCE_CARRIERS = [
    "BCBS", "AETNA", "CIGNA", "UHC", "UNITED", "HUMANA", "KAISER", "ANTHEM",
]

_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December"
)
_STREET_SUFFIX = (
    "Street|St|Avenue|Ave|Drive|Dr|Boulevard|Blvd|Road|Rd|Lane|Ln|Way|Court|Ct|"
    "Place|Pl|Circle|Cir|Terrace|Trail|Parkway|Pkwy"
)

# --- Compiled patterns ----------------------------------------------------
# Order matters only for tie-breaking in dedup; detection runs them all.
PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "PII_EMAIL": [re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")],
    "PII_PHONE": [
        re.compile(
            r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"
        )
    ],
    "PII_SSN": [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),       # dash
        re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b"),     # space
        re.compile(r"\b\d{9}\b"),                    # compact (lower confidence)
    ],
    "PII_DOB": [re.compile(rf"\b(?:{_MONTHS})\s+\d{{1,2}},\s+\d{{4}}\b")],
    "PII_ADDRESS": [
        re.compile(
            rf"\b\d{{1,6}}\s+[A-Za-z0-9.\- ]+?(?:{_STREET_SUFFIX})\.?,?"
            rf"\s*[A-Za-z. ]+,\s*[A-Z]{{2}}\s+\d{{5}}(?:-\d{{4}})?"
        )
    ],
    "PHI_MRN": [re.compile(r"\b(?:MRN|PT)-\d+\b")],
    "PHI_INSURANCE_ID": [
        re.compile(rf"\b(?:{'|'.join(INSURANCE_CARRIERS)})-[A-Z0-9\-]+\b")
    ],
    "PHI_DIAGNOSIS": [re.compile(rf"\b(?:{'|'.join(DIAGNOSIS_LEXICON)})\b")],
    "PHI_MEDICATION": [
        re.compile(rf"\b(?:{'|'.join(MEDICATION_NAMES)})\s+\d+\s?mg\b")
    ],
    "PHI_LAB_RESULT": [
        re.compile(
            rf"\b(?:{'|'.join(LAB_NAMES)})\s*:\s*\d+(?:\.\d+)?\s*"
            r"(?:%|mg/dL|mmol/L|mEq/L|g/dL|ng/mL|IU/L)"
        )
    ],
    "FIN_ACCOUNT": [re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b")],
    "FIN_TAX_ID": [re.compile(r"(?:EIN:?\s+)?\b\d{2}-\d{7}\b")],
    "LEGAL_CLIENT": [
        re.compile(
            r"\b[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+"
            r"(?:Trust|LLC|Inc\.?|Corp\.?|Foundation|Estate|Partners|Group|Holdings)\b"
        )
    ],
    "LEGAL_STRATEGY": [
        # Capture to end of line ([^\n]*, not [^.\n]*) so a decimal dollar amount
        # like "$2.4 million" does not truncate the privileged clause.
        re.compile(
            r"(?i)\b(?:settlement\s+is\s+advised[^\n]*"
            r"|settle\s+at\s+no\s+less\s+than[^\n]*"
            r"|our\s+position\s+is[^\n]*"
            r"|we\s+recommend\s+(?:settling|initiating)[^\n]*)"
        )
    ],
}

# Per-pattern confidence, indexed by (entity_type, pattern_index).
PATTERN_CONFIDENCE: dict[tuple[str, int], float] = {
    ("PII_EMAIL", 0): 0.99,
    ("PII_PHONE", 0): 0.95,
    ("PII_SSN", 0): 0.95,
    ("PII_SSN", 1): 0.90,
    ("PII_SSN", 2): 0.75,
    ("PII_DOB", 0): 0.90,
    ("PII_ADDRESS", 0): 0.85,
    ("PHI_MRN", 0): 0.85,
    ("PHI_INSURANCE_ID", 0): 0.85,
    ("PHI_DIAGNOSIS", 0): 0.90,
    ("PHI_MEDICATION", 0): 0.90,
    ("PHI_LAB_RESULT", 0): 0.85,
    ("FIN_ACCOUNT", 0): 0.90,
    ("FIN_TAX_ID", 0): 0.90,
    ("LEGAL_CLIENT", 0): 0.80,
    ("LEGAL_STRATEGY", 0): 0.75,
}

# Heuristic person-name pattern. Requires >= 2 capitalized, fully-bounded words so
# single tokens and partial matches inside other tokens (e.g. "HbA1c") are excluded.
# Uses [ \t] between words (not \s) so a name can never span a newline (Rule G-005).
NAME_PATTERN = re.compile(
    r"(?:(?:Dr|Mr|Mrs|Ms|Prof)\.?[ \t]+)?"
    r"[A-Z][a-z]+\b(?:[ \t]+(?:[A-Z]\.[ \t]+)?[A-Z][a-z]+\b)+"
    r"(?![ \t]*:)"  # a Title-Case phrase immediately before a colon is a field label
)
NAME_TITLE_PREFIX = re.compile(r"(?:Dr|Mr|Mrs|Ms|Prof)\.?\s+$")
NAME_CONFIDENCE = 0.85
