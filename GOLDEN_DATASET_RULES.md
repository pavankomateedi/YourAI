# Golden Dataset Rules
## Secure Context Pipeline — Test Fixture Specification & Ground Truth
**Version:** 2.0  
**Date:** 2026-05-21  
**Classification:** Confidential — Engineering Use Only

---

## Quick Reference

### Fixture Summary Table

| Fixture ID | Filename | Domain | Entity Count | Purpose | Key Eval |
|------------|----------|--------|--------------|---------|----------|
| F-001 | `F-001_medical_record_comprehensive.txt` | Healthcare | 14 | All required entity types in one doc | EVAL-OBF-006 |
| F-002 | `F-002_legal_brief_privilege.txt` | Legal | 8 | Privileged memo, client identity, strategy | EVAL-OBF-003, EVAL-OBF-007 |
| F-003 | `F-003_financial_disclosure.txt` | Finance | 10 | Repeated account numbers, idempotency | EVAL-OBF-001 |
| F-004 | `F-004_clean_medical_guidance.txt` | Healthcare | 0 | Zero-entity negative test | EVAL-CODE-005 |
| F-005 | `F-005_idempotency_stress.txt` | Healthcare | 14 | Same name+SSN repeated 7× each | EVAL-OBF-001 |
| F-006 | `F-006_low_confidence_entity.txt` | Healthcare | 4 | Ambiguous first name → low confidence | EVAL-OBF-007 |
| F-007 | `F-007_llm_response_deobfuscation.json` | Mixed | N/A | De-obfuscation round-trip ground truth | EVAL-DEOB-001–005 |
| F-008 | `F-008_multi_format_ssn.txt` | Mixed | 4 | SSN in 4 different format variants | EVAL-OBF-002 |
| F-009 | `F-009_adjacent_entities.txt` | Mixed | 6 | Two PII entities within 3 characters | EVAL-OBF-008 |

### How Claude Should Create Fixture Files

To create a fixture text file, write the fixture content exactly as shown in the code block to the path `tests/fixtures/golden/<FILENAME>.txt`. Shell command form is provided in each fixture section below.

To create the annotation JSON file, write the JSON block exactly as shown to the path `tests/fixtures/golden/<FILENAME>.json`.

**After creating each fixture file, run the validation script:**
```
python tests/fixtures/golden/validate_fixtures.py --fixture-dir tests/fixtures/golden
```
The script will catch any character-offset mismatches. Character offsets in annotations are provided as close approximations; if a mismatch is reported, adjust the offsets to match the actual file content (the script will tell you what it found at each offset).

---

## Entity Type Quick Reference

| Entity Type | Token Prefix | Example Value | Detection Method |
|-------------|--------------|---------------|-----------------|
| `PII_NAME` | `[PII_NAME_*]` | `Dr. Eleanor Hartwell` | NER (spaCy PERSON) |
| `PII_SSN` | `[PII_SSN_*]` | `543-67-8901` | Regex `\d{3}-\d{2}-\d{4}` |
| `PII_DOB` | `[PII_DOB_*]` | `March 14, 1972` | NER + date regex |
| `PII_ADDRESS` | `[PII_ADDRESS_*]` | `2847 Lakeview Drive, Austin, TX 78701` | NER (spaCy GPE + regex) |
| `PII_EMAIL` | `[PII_EMAIL_*]` | `eleanor.hartwell@example-clinic.org` | Regex RFC-5322 subset |
| `PII_PHONE` | `[PII_PHONE_*]` | `(512) 555-0147` | Regex E.164 + local formats |
| `PII_PASSPORT` | `[PII_PASSPORT_*]` | `A12345678` | Regex + classifier |
| `PII_DL` | `[PII_DL_*]` | `TX-DL-99123456` | Regex (state-aware) |
| `PHI_MRN` | `[PHI_MRN_*]` | `MRN-7293847` | Regex `MRN-\d+` |
| `PHI_DIAGNOSIS` | `[PHI_DIAGNOSIS_*]` | `Type 2 Diabetes Mellitus` | NER (medical NER model) |
| `PHI_MEDICATION` | `[PHI_MEDICATION_*]` | `Metformin 500mg` | NER + drug lexicon |
| `PHI_INSURANCE_ID` | `[PHI_INSURANCE_ID_*]` | `BCBS-TX-0042-8837291` | Regex + classifier |
| `PHI_LAB_RESULT` | `[PHI_LAB_RESULT_*]` | `HbA1c: 8.2%` | NER + lab lexicon |
| `FIN_ACCOUNT` | `[FIN_ACCOUNT_*]` | `4532-1234-5678-9012` | Regex + Luhn check |
| `FIN_TAX_ID` | `[FIN_TAX_ID_*]` | `EIN: 74-1234567` | Regex `\d{2}-\d{7}` |
| `LEGAL_CLIENT` | `[LEGAL_CLIENT_*]` | `Martinez Family Trust` | NER + legal entity classifier |
| `LEGAL_STRATEGY` | `[LEGAL_STRATEGY_*]` | `settle at no less than $2.4 million` | Classifier (privilege classifier) |

---

## Overview

This document defines the rules for creating, validating, and maintaining the golden dataset used to evaluate the Secure Context Pipeline. A "golden dataset" in this context means: a set of test fixture documents with pre-annotated ground-truth PII/PHI entities, expected obfuscation outputs, and expected de-obfuscation behavior. These fixtures drive the automated evals defined in `EVALS_SecureContextPipeline.md`.

**All PII values in golden dataset fixtures are entirely fictional.** No real person, patient, or client is represented. Values are constructed to be syntactically valid but not correspond to any real individual.

---

## Part 1: General Rules for Golden Dataset Construction

### Rule G-001: All Values Must Be Synthetic
Every name, SSN, date, address, account number, and clinical value in a fixture must be fabricated. Verifiable checks:
- SSNs: Must not match any real SSN. Use the format `9XX-XX-XXXX` (numbers beginning with 9 are invalid for real SSNs — ITIN range). Exception: test fixtures may use `543-67-8901` style (no known real-person mapping) if clearly documented as synthetic.
- Names: Must not be a known public figure. Use randomly generated first+last name combinations.
- Account numbers: Must fail Luhn algorithm check, or use a test-prefix (e.g., `4111-1111-1111-1111` from PCI test ranges).
- Medical values (MRN, diagnosis codes): Must use fictional identifiers; real ICD-10 codes may be used (they are public standards, not PII themselves).
- Addresses: Must be syntactically valid but should not correspond to a real person's home address. Use fictional street names or documented synthetic address ranges.

### Rule G-002: Every Fixture Must Have Ground-Truth Annotation
Each fixture document must be accompanied by a JSON annotation file containing:
```json
{
  "fixture_id": "string",
  "fixture_file": "string",
  "description": "string",
  "entities": [
    {
      "entity_type": "string",       // e.g., "PII_NAME"
      "original_value": "string",    // exact string as it appears in the document
      "start_char": 0,               // character offset (0-indexed)
      "end_char": 0,                 // character offset (exclusive)
      "expected_confidence_min": 0.0 // minimum acceptable detection confidence
    }
  ]
}
```

### Rule G-003: Ground-Truth Spans Must Be Exact
The `original_value` in the annotation must be a byte-exact substring of the fixture text at `[start_char:end_char]`. Any leading/trailing whitespace must be excluded. Automated validation enforces this.

### Rule G-004: Minimum Entity Coverage per Fixture
Each fixture must contain at least the following entity types to qualify as a "comprehensive" fixture (required for EVAL-OBF-006):
- At least one entity of each required type: `PII_NAME, PII_SSN, PII_DOB, PII_ADDRESS, PII_EMAIL, PII_PHONE`
- At least one entity of each PHI type: `PHI_MRN, PHI_DIAGNOSIS, PHI_MEDICATION, PHI_INSURANCE_ID, PHI_LAB_RESULT`
- At least one financial entity: `FIN_ACCOUNT` or `FIN_TAX_ID`
- At least one legal entity: `LEGAL_CLIENT`

Domain-specific fixtures (medical-only, legal-only) do not need to meet all 14 types.

### Rule G-005: No Entity Shall Span Across a Newline Character
Entity spans must not include newline characters. If a name appears with a line break ("Dr. Eleanor\nHartwell"), it must be annotated as two separate entities or the fixture must be reformatted.

### Rule G-006: Repeated Entities Must Appear in Multiple Spans
If the same value appears more than once in a fixture, each occurrence must be independently annotated with its own `start_char` and `end_char`. This tests the idempotency rule (EVAL-OBF-001).

### Rule G-007: Edge Cases Must Be Represented
The golden dataset must include at least one fixture for each of the following edge cases:
- A value that appears in multiple formats (e.g., DOB as "01/15/1972" and "January 15, 1972" in the same doc)
- A low-confidence entity (injected via annotation `expected_confidence_min: 0.45`) that must trigger redaction
- A document with zero PII entities
- A document where the same entity value appears 5+ times (idempotency stress test)
- A long document (≥ 2,000 words) with ≥ 20 entities (performance test)
- A document with entities in close proximity (two entities within 5 characters of each other)

### Rule G-008: Fixture Files Are Immutable After Validation
Once a fixture file passes automated validation (see Validation Script below), it is frozen. Changes require a version bump and re-validation. This ensures test results are comparable across implementations.

### Rule G-009: Obfuscated Output Is Non-Deterministic — Annotate Token Patterns, Not Values
Because token suffixes are random, the golden dataset cannot specify the exact token a fixture entity will produce. Instead, annotations specify:
- Expected token prefix (e.g., `[PII_NAME_*]`)
- Whether each entity should be tokenized or pseudonymized
- For pseudonymization: the semantic constraints on the pseudonym (same gender? same age range?)

### Rule G-010: De-obfuscation Ground Truth Specifies Round-Trip Restoration
For each obfuscation event, the golden dataset specifies:
- Input: the obfuscated text (with tokens)
- Expected output: the original text (with original values restored)
- The ground-truth comparison is an exact string match after normalization (strip trailing whitespace)

---

## Part 2: Fixture Catalog

### Fixture F-001: Comprehensive Medical Record

**What this tests:** EVAL-OBF-006 (all 14 entity type coverage), EVAL-OBF-001 (basic tokenization), EVAL-DEOB-001 (basic round-trip)

**File:** `tests/fixtures/golden/F-001_medical_record_comprehensive.txt`  
**Description:** A complete patient record covering all required PII + PHI entity types. Primary fixture for EVAL-OBF-006 (entity coverage).  
**Entity Count:** 14 entities (one of each required type)  
**Domain:** Healthcare  
**Regulatory Scope:** HIPAA PHI + PII

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-001_medical_record_comprehensive.txt << 'EOF'
PATIENT RECORD — CONFIDENTIAL
==============================

Patient Name: Dr. Eleanor Hartwell
Social Security Number: 543-67-8901
Date of Birth: March 14, 1972
Home Address: 2847 Lakeview Drive, Austin, TX 78701
Contact Email: eleanor.hartwell@example-clinic.org
Phone Number: (512) 555-0147

CLINICAL INFORMATION
Medical Record Number: MRN-7293847
Insurance ID: BCBS-TX-0042-8837291
Primary Diagnosis: Type 2 Diabetes Mellitus
Current Medication: Metformin 500mg (twice daily with meals)
Latest Lab Result: HbA1c: 8.2% — above target of 7.0%

FINANCIAL & LEGAL INFORMATION
Billing Account: 4532-1234-5678-9012
Tax Identification: EIN: 74-1234567
Legal Representative: Martinez Family Trust
EOF
```

**Fixture Text:**
```
PATIENT RECORD — CONFIDENTIAL
==============================

Patient Name: Dr. Eleanor Hartwell
Social Security Number: 543-67-8901
Date of Birth: March 14, 1972
Home Address: 2847 Lakeview Drive, Austin, TX 78701
Contact Email: eleanor.hartwell@example-clinic.org
Phone Number: (512) 555-0147

CLINICAL INFORMATION
Medical Record Number: MRN-7293847
Insurance ID: BCBS-TX-0042-8837291
Primary Diagnosis: Type 2 Diabetes Mellitus
Current Medication: Metformin 500mg (twice daily with meals)
Latest Lab Result: HbA1c: 8.2% — above target of 7.0%

FINANCIAL & LEGAL INFORMATION
Billing Account: 4532-1234-5678-9012
Tax Identification: EIN: 74-1234567
Legal Representative: Martinez Family Trust
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-001):**
```json
{
  "fixture_id": "F-001",
  "fixture_file": "tests/fixtures/golden/F-001_medical_record_comprehensive.txt",
  "description": "Comprehensive medical record — all 14 entity types",
  "entities": [
    {
      "entity_type": "PII_NAME",
      "original_value": "Dr. Eleanor Hartwell",
      "start_char": 63,
      "end_char": 83,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "543-67-8901",
      "start_char": 110,
      "end_char": 121,
      "expected_confidence_min": 0.95
    },
    {
      "entity_type": "PII_DOB",
      "original_value": "March 14, 1972",
      "start_char": 138,
      "end_char": 152,
      "expected_confidence_min": 0.90
    },
    {
      "entity_type": "PII_ADDRESS",
      "original_value": "2847 Lakeview Drive, Austin, TX 78701",
      "start_char": 167,
      "end_char": 204,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PII_EMAIL",
      "original_value": "eleanor.hartwell@example-clinic.org",
      "start_char": 220,
      "end_char": 255,
      "expected_confidence_min": 0.99
    },
    {
      "entity_type": "PII_PHONE",
      "original_value": "(512) 555-0147",
      "start_char": 271,
      "end_char": 285,
      "expected_confidence_min": 0.95
    },
    {
      "entity_type": "PHI_MRN",
      "original_value": "MRN-7293847",
      "start_char": 318,
      "end_char": 329,
      "expected_confidence_min": 0.80
    },
    {
      "entity_type": "PHI_INSURANCE_ID",
      "original_value": "BCBS-TX-0042-8837291",
      "start_char": 344,
      "end_char": 364,
      "expected_confidence_min": 0.80
    },
    {
      "entity_type": "PHI_DIAGNOSIS",
      "original_value": "Type 2 Diabetes Mellitus",
      "start_char": 387,
      "end_char": 411,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PHI_MEDICATION",
      "original_value": "Metformin 500mg",
      "start_char": 431,
      "end_char": 446,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PHI_LAB_RESULT",
      "original_value": "HbA1c: 8.2%",
      "start_char": 484,
      "end_char": 495,
      "expected_confidence_min": 0.80
    },
    {
      "entity_type": "FIN_ACCOUNT",
      "original_value": "4532-1234-5678-9012",
      "start_char": 545,
      "end_char": 564,
      "expected_confidence_min": 0.90
    },
    {
      "entity_type": "FIN_TAX_ID",
      "original_value": "EIN: 74-1234567",
      "start_char": 583,
      "end_char": 598,
      "expected_confidence_min": 0.90
    },
    {
      "entity_type": "LEGAL_CLIENT",
      "original_value": "Martinez Family Trust",
      "start_char": 621,
      "end_char": 642,
      "expected_confidence_min": 0.75
    }
  ]
}
```

---

### Fixture F-002: Legal Brief with Privilege Indicators

**What this tests:** EVAL-OBF-003 (privilege classification), EVAL-OBF-007 (redaction of client identity), EVAL-OBF-001 (tokenization of name + SSN + contact)

**File:** `tests/fixtures/golden/F-002_legal_brief_privilege.txt`  
**Description:** A legal memorandum containing attorney-client privileged content, client identity, and settlement terms.  
**Entity Count:** 8 entities  
**Domain:** Legal  
**Regulatory Scope:** Attorney-Client Privilege, Work Product Doctrine

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-002_legal_brief_privilege.txt << 'EOF'
PRIVILEGED AND CONFIDENTIAL
ATTORNEY-CLIENT COMMUNICATION
WORK PRODUCT DOCTRINE

To: Senior Partner Marcus R. Webb
From: Associate Counsel
Re: Martinez Family Trust v. Hargrove Capital LLC
Date: April 3, 2026

CASE STRATEGY MEMORANDUM

Our client, the Martinez Family Trust (represented by trustee Priya Okonkwo,
SSN: 987-12-3456), has authorized us to proceed with settlement discussions.
Our position is to settle at no less than $2.4 million based on the strength
of documentary evidence and expert witness testimony secured to date.

The opposing counsel has indicated willingness to negotiate. We recommend
initiating formal mediation through JAMS no later than May 15, 2026.
All communications should be directed to our client contact at:
priya.okonkwo@martinez-trust.example.com or (415) 555-0293.

Confidential work product — do not distribute.
EOF
```

**Fixture Text:**
```
PRIVILEGED AND CONFIDENTIAL
ATTORNEY-CLIENT COMMUNICATION
WORK PRODUCT DOCTRINE

To: Senior Partner Marcus R. Webb
From: Associate Counsel
Re: Martinez Family Trust v. Hargrove Capital LLC
Date: April 3, 2026

CASE STRATEGY MEMORANDUM

Our client, the Martinez Family Trust (represented by trustee Priya Okonkwo,
SSN: 987-12-3456), has authorized us to proceed with settlement discussions.
Our position is to settle at no less than $2.4 million based on the strength
of documentary evidence and expert witness testimony secured to date.

The opposing counsel has indicated willingness to negotiate. We recommend
initiating formal mediation through JAMS no later than May 15, 2026.
All communications should be directed to our client contact at:
priya.okonkwo@martinez-trust.example.com or (415) 555-0293.

Confidential work product — do not distribute.
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-002):**
```json
{
  "fixture_id": "F-002",
  "fixture_file": "tests/fixtures/golden/F-002_legal_brief_privilege.txt",
  "description": "Privileged legal memo with client identity and case strategy",
  "entities": [
    {
      "entity_type": "PII_NAME",
      "original_value": "Marcus R. Webb",
      "start_char": 115,
      "end_char": 129,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "LEGAL_CLIENT",
      "original_value": "Martinez Family Trust",
      "start_char": 187,
      "end_char": 208,
      "expected_confidence_min": 0.75
    },
    {
      "entity_type": "PII_NAME",
      "original_value": "Priya Okonkwo",
      "start_char": 235,
      "end_char": 248,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "987-12-3456",
      "start_char": 255,
      "end_char": 266,
      "expected_confidence_min": 0.95
    },
    {
      "entity_type": "LEGAL_STRATEGY",
      "original_value": "settle at no less than $2.4 million",
      "start_char": 295,
      "end_char": 330,
      "expected_confidence_min": 0.70
    },
    {
      "entity_type": "PII_EMAIL",
      "original_value": "priya.okonkwo@martinez-trust.example.com",
      "start_char": 530,
      "end_char": 570,
      "expected_confidence_min": 0.99
    },
    {
      "entity_type": "PII_PHONE",
      "original_value": "(415) 555-0293",
      "start_char": 574,
      "end_char": 588,
      "expected_confidence_min": 0.95
    },
    {
      "entity_type": "LEGAL_CLIENT",
      "original_value": "Martinez Family Trust",
      "start_char": 187,
      "end_char": 208,
      "expected_confidence_min": 0.75,
      "note": "Second occurrence at different location — annotate both"
    }
  ]
}
```

---

### Fixture F-003: Financial Disclosure Document

**What this tests:** EVAL-OBF-001 (idempotency — same account token for all 3 occurrences), EVAL-OBF-002 (FIN_ACCOUNT detection), EVAL-OBF-006 (multi-entity type coverage)

**File:** `tests/fixtures/golden/F-003_financial_disclosure.txt`  
**Description:** A financial advisory client disclosure with account numbers, tax IDs, and transaction history.  
**Domain:** Finance  
**Regulatory Scope:** GLBA, SOX, PCI-DSS

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-003_financial_disclosure.txt << 'EOF'
CONFIDENTIAL FINANCIAL DISCLOSURE
Client: Raj Patel
Date of Birth: September 7, 1968
Tax ID (EIN): 23-4567890
Primary Account: 4111-2222-3333-4444
Secondary Account: SAVINGS-77-8812345

Transaction Summary — Q1 2026:
- Wire Transfer from Acct 4111-2222-3333-4444: $125,000 on 2026-01-15
- Wire Transfer from Acct 4111-2222-3333-4444: $87,500 on 2026-02-28
- Deposit to SAVINGS-77-8812345: $212,500 on 2026-03-31

Contact: raj.patel.advisor@example-finance.com
Mobile: (713) 555-0384
Home Address: 9102 Westwood Boulevard, Houston, TX 77001
EOF
```

**Fixture Text:**
```
CONFIDENTIAL FINANCIAL DISCLOSURE
Client: Raj Patel
Date of Birth: September 7, 1968
Tax ID (EIN): 23-4567890
Primary Account: 4111-2222-3333-4444
Secondary Account: SAVINGS-77-8812345

Transaction Summary — Q1 2026:
- Wire Transfer from Acct 4111-2222-3333-4444: $125,000 on 2026-01-15
- Wire Transfer from Acct 4111-2222-3333-4444: $87,500 on 2026-02-28
- Deposit to SAVINGS-77-8812345: $212,500 on 2026-03-31

Contact: raj.patel.advisor@example-finance.com
Mobile: (713) 555-0384
Home Address: 9102 Westwood Boulevard, Houston, TX 77001
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-003):**
```json
{
  "fixture_id": "F-003",
  "fixture_file": "tests/fixtures/golden/F-003_financial_disclosure.txt",
  "description": "Financial disclosure — multiple account numbers, DOB, tax ID, repeated account references",
  "entities": [
    {
      "entity_type": "PII_NAME",
      "original_value": "Raj Patel",
      "start_char": 43,
      "end_char": 52,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PII_DOB",
      "original_value": "September 7, 1968",
      "start_char": 69,
      "end_char": 86,
      "expected_confidence_min": 0.90
    },
    {
      "entity_type": "FIN_TAX_ID",
      "original_value": "EIN): 23-4567890",
      "start_char": 96,
      "end_char": 112,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "FIN_ACCOUNT",
      "original_value": "4111-2222-3333-4444",
      "start_char": 130,
      "end_char": 149,
      "expected_confidence_min": 0.90,
      "note": "First occurrence — idempotency test requires same token on all 3 occurrences"
    },
    {
      "entity_type": "FIN_ACCOUNT",
      "original_value": "SAVINGS-77-8812345",
      "start_char": 170,
      "end_char": 188,
      "expected_confidence_min": 0.80
    },
    {
      "entity_type": "FIN_ACCOUNT",
      "original_value": "4111-2222-3333-4444",
      "start_char": 240,
      "end_char": 259,
      "expected_confidence_min": 0.90,
      "note": "Second occurrence — must map to same token as first"
    },
    {
      "entity_type": "FIN_ACCOUNT",
      "original_value": "4111-2222-3333-4444",
      "start_char": 300,
      "end_char": 319,
      "expected_confidence_min": 0.90,
      "note": "Third occurrence — must map to same token"
    },
    {
      "entity_type": "PII_EMAIL",
      "original_value": "raj.patel.advisor@example-finance.com",
      "start_char": 370,
      "end_char": 407,
      "expected_confidence_min": 0.99
    },
    {
      "entity_type": "PII_PHONE",
      "original_value": "(713) 555-0384",
      "start_char": 416,
      "end_char": 430,
      "expected_confidence_min": 0.95
    },
    {
      "entity_type": "PII_ADDRESS",
      "original_value": "9102 Westwood Boulevard, Houston, TX 77001",
      "start_char": 447,
      "end_char": 489,
      "expected_confidence_min": 0.85
    }
  ],
  "idempotency_assertions": [
    {
      "entities_with_same_value": ["4111-2222-3333-4444"],
      "expected_behavior": "all_occurrences_map_to_same_token"
    }
  ]
}
```

---

### Fixture F-004: Clean Document (Zero PII — Negative Test)

**What this tests:** EVAL-CODE-005 (entity type not found / graceful empty-list handling), EVAL-OBF-001 (pipeline completes without error on clean input)

**File:** `tests/fixtures/golden/F-004_clean_medical_guidance.txt`  
**Description:** A document with no PII/PHI — tests that the pipeline handles zero-entity documents gracefully.

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-004_clean_medical_guidance.txt << 'EOF'
GENERAL DIABETES MANAGEMENT GUIDANCE

Patients with Type 2 Diabetes are advised to maintain blood glucose levels
within target ranges as established by their care team. Regular monitoring
using a home glucometer is recommended at least twice daily.

Dietary modifications include reducing refined carbohydrates, increasing
fiber intake, and maintaining consistent meal timing. Physical activity
of at least 150 minutes of moderate exercise per week is associated with
improved glycemic control.

Medications such as Metformin are commonly prescribed. Patients should
not adjust dosage without consulting their physician. Annual HbA1c testing
is standard of care for monitoring long-term glucose management.

This document does not contain patient-specific information.
EOF
```

**Fixture Text:**
```
GENERAL DIABETES MANAGEMENT GUIDANCE

Patients with Type 2 Diabetes are advised to maintain blood glucose levels
within target ranges as established by their care team. Regular monitoring
using a home glucometer is recommended at least twice daily.

Dietary modifications include reducing refined carbohydrates, increasing
fiber intake, and maintaining consistent meal timing. Physical activity
of at least 150 minutes of moderate exercise per week is associated with
improved glycemic control.

Medications such as Metformin are commonly prescribed. Patients should
not adjust dosage without consulting their physician. Annual HbA1c testing
is standard of care for monitoring long-term glucose management.

This document does not contain patient-specific information.
```

**Ground-Truth Annotation (F-004):**
```json
{
  "fixture_id": "F-004",
  "fixture_file": "tests/fixtures/golden/F-004_clean_medical_guidance.txt",
  "description": "No PII/PHI — negative detection test. General medical guidance only.",
  "entities": [],
  "expected_behavior": {
    "detection": "empty_entity_list",
    "obfuscation": "text_unchanged",
    "pipeline": "completes_without_error"
  }
}
```

---

### Fixture F-005: Idempotency Stress Test (Entity Repeated 7 Times)

**What this tests:** EVAL-OBF-001 (within-session determinism), idempotency across 7 repetitions of same name and SSN

**File:** `tests/fixtures/golden/F-005_idempotency_stress.txt`  
**Description:** A document where "Dr. Eleanor Hartwell" and their SSN appear 7 times each. Tests EVAL-OBF-001 (within-session determinism).

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-005_idempotency_stress.txt << 'EOF'
Dr. Eleanor Hartwell was seen on Monday.
SSN on file: 543-67-8901.
Dr. Eleanor Hartwell reported fatigue.
Re-verification SSN: 543-67-8901.
The care plan for Dr. Eleanor Hartwell was updated.
Insurance verified for SSN 543-67-8901.
Dr. Eleanor Hartwell consented to treatment.
SSN 543-67-8901 confirmed for billing.
Follow-up scheduled for Dr. Eleanor Hartwell.
Account linked to SSN: 543-67-8901.
Dr. Eleanor Hartwell was discharged on Friday.
Final billing: SSN 543-67-8901.
Dr. Eleanor Hartwell's record is closed.
SSN 543-67-8901 archived.
EOF
```

**Fixture Text:**
```
Dr. Eleanor Hartwell was seen on Monday.
SSN on file: 543-67-8901.
Dr. Eleanor Hartwell reported fatigue.
Re-verification SSN: 543-67-8901.
The care plan for Dr. Eleanor Hartwell was updated.
Insurance verified for SSN 543-67-8901.
Dr. Eleanor Hartwell consented to treatment.
SSN 543-67-8901 confirmed for billing.
Follow-up scheduled for Dr. Eleanor Hartwell.
Account linked to SSN: 543-67-8901.
Dr. Eleanor Hartwell was discharged on Friday.
Final billing: SSN 543-67-8901.
Dr. Eleanor Hartwell's record is closed.
SSN 543-67-8901 archived.
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-005):**
```json
{
  "fixture_id": "F-005",
  "fixture_file": "tests/fixtures/golden/F-005_idempotency_stress.txt",
  "description": "Same name + SSN repeated 7 times — idempotency test",
  "entities": [
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 0, "end_char": 20, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 37, "end_char": 48, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 50, "end_char": 70, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 97, "end_char": 108, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 114, "end_char": 134, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 165, "end_char": 176, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 178, "end_char": 198, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 221, "end_char": 232, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 258, "end_char": 278, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 307, "end_char": 318, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 320, "end_char": 340, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 360, "end_char": 371, "expected_confidence_min": 0.95 },
    { "entity_type": "PII_NAME", "original_value": "Dr. Eleanor Hartwell", "start_char": 373, "end_char": 393, "expected_confidence_min": 0.85 },
    { "entity_type": "PII_SSN", "original_value": "543-67-8901", "start_char": 414, "end_char": 425, "expected_confidence_min": 0.95 }
  ],
  "idempotency_assertions": [
    {
      "entities_with_same_value": ["Dr. Eleanor Hartwell"],
      "expected_token_count": 1,
      "note": "All 7 occurrences must map to the same single token"
    },
    {
      "entities_with_same_value": ["543-67-8901"],
      "expected_token_count": 1,
      "note": "All 7 SSN occurrences must map to the same single token"
    }
  ]
}
```

---

### Fixture F-006: Low-Confidence Entity Graceful Degradation

**What this tests:** EVAL-OBF-007 (graceful redaction of low-confidence entities), EVAL-OBF-003 (mixed confidence in single document)

**File:** `tests/fixtures/golden/F-006_low_confidence_entity.txt`  
**Description:** A document where one entity is ambiguous (a common first name with no last name, no contextual signals). Tests graceful redaction (EVAL-OBF-007).

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-006_low_confidence_entity.txt << 'EOF'
CLINICAL NOTE
The nurse spoke with John about his medication schedule.
The care team confirmed his dose of Metformin 500mg.
MRN: MRN-7293847
Dr. Eleanor Hartwell reviewed the case.
EOF
```

**Fixture Text:**
```
CLINICAL NOTE
The nurse spoke with John about his medication schedule.
The care team confirmed his dose of Metformin 500mg.
MRN: MRN-7293847
Dr. Eleanor Hartwell reviewed the case.
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-006):**
```json
{
  "fixture_id": "F-006",
  "fixture_file": "tests/fixtures/golden/F-006_low_confidence_entity.txt",
  "description": "Low-confidence ambiguous first name 'John' — must trigger redaction not passthrough",
  "entities": [
    {
      "entity_type": "PII_NAME",
      "original_value": "John",
      "start_char": 28,
      "end_char": 32,
      "expected_confidence_min": 0.0,
      "expected_confidence_max": 0.60,
      "note": "Isolated first name without context — expected low confidence. Must be REDACTED."
    },
    {
      "entity_type": "PHI_MEDICATION",
      "original_value": "Metformin 500mg",
      "start_char": 82,
      "end_char": 97,
      "expected_confidence_min": 0.85
    },
    {
      "entity_type": "PHI_MRN",
      "original_value": "MRN-7293847",
      "start_char": 103,
      "end_char": 114,
      "expected_confidence_min": 0.80
    },
    {
      "entity_type": "PII_NAME",
      "original_value": "Dr. Eleanor Hartwell",
      "start_char": 119,
      "end_char": 139,
      "expected_confidence_min": 0.85
    }
  ],
  "redaction_assertions": [
    {
      "entity_value": "John",
      "expected_output": "[REDACTED]",
      "reason": "confidence_below_threshold"
    }
  ]
}
```

---

### Fixture F-007: LLM Response De-obfuscation Ground Truth

**What this tests:** EVAL-DEOB-001 (basic token restoration), EVAL-DEOB-002 (possessive inflection), EVAL-DEOB-003 (vault miss → [UNAVAILABLE]), EVAL-DEOB-004 (non-PII text preservation), EVAL-DEOB-005 (multiple tokens per response)

**File:** `tests/fixtures/golden/F-007_llm_response_deobfuscation.json`  
**Description:** Pre-built LLM responses containing tokens, with expected restored outputs. Used for EVAL-DEOB-001 through EVAL-DEOB-005. This fixture has no corresponding `.txt` file — the entire fixture is the JSON.

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-007_llm_response_deobfuscation.json << 'EOF'
{
  "fixture_id": "F-007",
  ...
}
EOF
```
(Use the full JSON content below.)

```json
{
  "fixture_id": "F-007",
  "description": "LLM response de-obfuscation ground truth cases",
  "session_vault_state": {
    "[PII_NAME_a3f2c1d4]": "Dr. Eleanor Hartwell",
    "[PII_SSN_b7e2a1c3]": "543-67-8901",
    "[PII_DOB_c9d3e4f5]": "March 14, 1972",
    "[PHI_DIAGNOSIS_2c8a4d7b]": "Type 2 Diabetes Mellitus",
    "[PHI_MEDICATION_9f1a3e2b]": "Metformin 500mg",
    "[PHI_MRN_5e8b2d1a]": "MRN-7293847",
    "[FIN_ACCOUNT_4d7c9a1e]": "4532-1234-5678-9012"
  },
  "test_cases": [
    {
      "case_id": "TC-001",
      "description": "Simple token restoration — all tokens echoed by LLM",
      "llm_response": "Patient [PII_NAME_a3f2c1d4] (MRN: [PHI_MRN_5e8b2d1a]) has a diagnosis of [PHI_DIAGNOSIS_2c8a4d7b] and is prescribed [PHI_MEDICATION_9f1a3e2b].",
      "expected_output": "Patient Dr. Eleanor Hartwell (MRN: MRN-7293847) has a diagnosis of Type 2 Diabetes Mellitus and is prescribed Metformin 500mg.",
      "expected_tokens_restored": 4,
      "expected_tokens_missed": 0
    },
    {
      "case_id": "TC-002",
      "description": "Possessive inflection — [PII_NAME_a3f2c1d4]'s",
      "llm_response": "[PII_NAME_a3f2c1d4]'s diagnosis of [PHI_DIAGNOSIS_2c8a4d7b] was confirmed on [PII_DOB_c9d3e4f5].",
      "expected_output": "Dr. Eleanor Hartwell's diagnosis of Type 2 Diabetes Mellitus was confirmed on March 14, 1972.",
      "expected_tokens_restored": 3,
      "expected_tokens_missed": 0
    },
    {
      "case_id": "TC-003",
      "description": "Vault miss — token not in vault",
      "llm_response": "The patient [PII_NAME_FFFFFFFF] should follow up with [PII_NAME_a3f2c1d4].",
      "expected_output": "The patient [UNAVAILABLE] should follow up with Dr. Eleanor Hartwell.",
      "expected_tokens_restored": 1,
      "expected_tokens_missed": 1,
      "vault_miss_tokens": ["[PII_NAME_FFFFFFFF]"]
    },
    {
      "case_id": "TC-004",
      "description": "Non-PII text preservation — surrounding text must be unchanged",
      "llm_response": "The patient [PII_NAME_a3f2c1d4] has shown improvement. Blood pressure is 120/80 mmHg. Follow-up in 3 weeks.",
      "expected_output": "The patient Dr. Eleanor Hartwell has shown improvement. Blood pressure is 120/80 mmHg. Follow-up in 3 weeks.",
      "expected_tokens_restored": 1,
      "expected_tokens_missed": 0
    },
    {
      "case_id": "TC-005",
      "description": "Multiple tokens of same type in one response",
      "llm_response": "Account [FIN_ACCOUNT_4d7c9a1e] belongs to [PII_NAME_a3f2c1d4] (SSN: [PII_SSN_b7e2a1c3]).",
      "expected_output": "Account 4532-1234-5678-9012 belongs to Dr. Eleanor Hartwell (SSN: 543-67-8901).",
      "expected_tokens_restored": 3,
      "expected_tokens_missed": 0
    },
    {
      "case_id": "TC-006",
      "description": "Response with zero tokens — no PII in LLM output",
      "llm_response": "The patient's blood pressure reading is within normal range. No further action is required at this time.",
      "expected_output": "The patient's blood pressure reading is within normal range. No further action is required at this time.",
      "expected_tokens_restored": 0,
      "expected_tokens_missed": 0
    },
    {
      "case_id": "TC-007",
      "description": "Token at start and end of response",
      "llm_response": "[PII_NAME_a3f2c1d4] was the subject of this assessment. All records are stored under [PHI_MRN_5e8b2d1a].",
      "expected_output": "Dr. Eleanor Hartwell was the subject of this assessment. All records are stored under MRN-7293847.",
      "expected_tokens_restored": 2,
      "expected_tokens_missed": 0
    }
  ]
}
```

---

### Fixture F-008: Multi-Format SSN Detection

**What this tests:** EVAL-OBF-002 (SSN format variants — dashes, spaces, no separator, in-sentence), tests that the regex engine handles all 4 canonical SSN representations

**File:** `tests/fixtures/golden/F-008_multi_format_ssn.txt`  
**Description:** Four SSN values each in a different format variant. The pipeline must detect all four as `PII_SSN` regardless of separator style. This is a common regex edge case.  
**Entity Count:** 4 entities  
**Domain:** Mixed (administrative)  
**Regulatory Scope:** PII

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-008_multi_format_ssn.txt << 'EOF'
SSN FORMAT VARIANT TEST

Standard dash format: 912-34-5678
Space-separated format: 923 45 6789
No separator (compact): 934567890
In a sentence: The patient's social security number is 945-67-8901 as listed on file.
EOF
```

**Fixture Text:**
```
SSN FORMAT VARIANT TEST

Standard dash format: 912-34-5678
Space-separated format: 923 45 6789
No separator (compact): 934567890
In a sentence: The patient's social security number is 945-67-8901 as listed on file.
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-008):**
```json
{
  "fixture_id": "F-008",
  "fixture_file": "tests/fixtures/golden/F-008_multi_format_ssn.txt",
  "description": "SSN in 4 format variants: dashes, spaces, no separator, embedded in sentence",
  "entities": [
    {
      "entity_type": "PII_SSN",
      "original_value": "912-34-5678",
      "start_char": 46,
      "end_char": 57,
      "expected_confidence_min": 0.95,
      "note": "Standard dash-separated SSN"
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "923 45 6789",
      "start_char": 81,
      "end_char": 92,
      "expected_confidence_min": 0.90,
      "note": "Space-separated SSN — requires space-tolerant regex variant"
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "934567890",
      "start_char": 116,
      "end_char": 125,
      "expected_confidence_min": 0.75,
      "note": "Compact no-separator SSN — lower confidence expected due to format ambiguity"
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "945-67-8901",
      "start_char": 183,
      "end_char": 194,
      "expected_confidence_min": 0.95,
      "note": "SSN embedded in natural-language sentence — detector must parse through surrounding text"
    }
  ],
  "format_coverage": {
    "dash_separated": true,
    "space_separated": true,
    "no_separator": true,
    "in_sentence": true
  }
}
```

---

### Fixture F-009: Adjacent Entities

**What this tests:** EVAL-OBF-008 (span non-merging — two PII entities within 3 characters must be annotated independently, not merged into a single span), EVAL-OBF-001 (both entities correctly tokenized)

**File:** `tests/fixtures/golden/F-009_adjacent_entities.txt`  
**Description:** Multiple cases where two PII entities appear within 3 characters of each other (separated only by punctuation or a single space). Tests that the detector produces two separate, non-overlapping spans rather than merging them into one.  
**Entity Count:** 6 entities (3 pairs of adjacent entities)  
**Domain:** Mixed  
**Regulatory Scope:** PII

**How to create the file:**
```sh
cat > tests/fixtures/golden/F-009_adjacent_entities.txt << 'EOF'
ADJACENT ENTITY TEST CASES

Case 1 — Name followed immediately by SSN in parentheses:
Name: John Smith (SSN: 943-67-8901)

Case 2 — Email directly after name with no space, colon only:
Contact: Priya Okonkwo:priya.okonkwo@example.org

Case 3 — Two names separated by a slash:
Attending/Consulting: Dr. Amos Vega/Dr. Sara Lund
EOF
```

**Fixture Text:**
```
ADJACENT ENTITY TEST CASES

Case 1 — Name followed immediately by SSN in parentheses:
Name: John Smith (SSN: 943-67-8901)

Case 2 — Email directly after name with no space, colon only:
Contact: Priya Okonkwo:priya.okonkwo@example.org

Case 3 — Two names separated by a slash:
Attending/Consulting: Dr. Amos Vega/Dr. Sara Lund
```

> **Note on offsets:** Character offsets below are approximate. Run `validate_fixtures.py` after creating the file — it will report exact mismatches and the correct substring found at each offset.

**Ground-Truth Annotation (F-009):**
```json
{
  "fixture_id": "F-009",
  "fixture_file": "tests/fixtures/golden/F-009_adjacent_entities.txt",
  "description": "Pairs of PII entities within 3 characters of each other — must not be merged into a single span",
  "entities": [
    {
      "entity_type": "PII_NAME",
      "original_value": "John Smith",
      "start_char": 69,
      "end_char": 79,
      "expected_confidence_min": 0.85,
      "note": "Case 1: name entity; gap to SSN is 2 chars ' ('"
    },
    {
      "entity_type": "PII_SSN",
      "original_value": "943-67-8901",
      "start_char": 86,
      "end_char": 97,
      "expected_confidence_min": 0.95,
      "note": "Case 1: SSN entity; immediately follows name with ' (SSN: ' separator"
    },
    {
      "entity_type": "PII_NAME",
      "original_value": "Priya Okonkwo",
      "start_char": 153,
      "end_char": 166,
      "expected_confidence_min": 0.85,
      "note": "Case 2: name entity; gap to email is 1 char ':'"
    },
    {
      "entity_type": "PII_EMAIL",
      "original_value": "priya.okonkwo@example.org",
      "start_char": 167,
      "end_char": 192,
      "expected_confidence_min": 0.99,
      "note": "Case 2: email entity; immediately follows name with ':' separator only"
    },
    {
      "entity_type": "PII_NAME",
      "original_value": "Dr. Amos Vega",
      "start_char": 237,
      "end_char": 250,
      "expected_confidence_min": 0.85,
      "note": "Case 3: first name in slash-separated pair; gap to next name is 1 char '/'"
    },
    {
      "entity_type": "PII_NAME",
      "original_value": "Dr. Sara Lund",
      "start_char": 251,
      "end_char": 264,
      "expected_confidence_min": 0.85,
      "note": "Case 3: second name in slash-separated pair; must be a distinct span from the first"
    }
  ],
  "adjacency_assertions": [
    {
      "pair": ["John Smith", "943-67-8901"],
      "gap_chars": 7,
      "expected_behavior": "two_distinct_non_overlapping_spans"
    },
    {
      "pair": ["Priya Okonkwo", "priya.okonkwo@example.org"],
      "gap_chars": 1,
      "expected_behavior": "two_distinct_non_overlapping_spans"
    },
    {
      "pair": ["Dr. Amos Vega", "Dr. Sara Lund"],
      "gap_chars": 1,
      "expected_behavior": "two_distinct_non_overlapping_spans"
    }
  ]
}
```

---

## Part 3: Validation Script

The following is the complete, fully runnable validation script. Save it to `tests/fixtures/golden/validate_fixtures.py`.

```python
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


def validate_annotation(fixture_text: str, annotation: dict, annotation_path: str) -> list[str]:
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


def find_fixture_pairs(fixture_dir: Path) -> list[tuple[Path, Path | None]]:
    """
    For each .json annotation file, find the corresponding .txt file (if any).
    Returns list of (json_path, txt_path_or_None) pairs.
    F-007 style fixtures have no .txt companion — txt_path will be None.
    """
    pairs = []
    for json_path in sorted(fixture_dir.glob("*.json")):
        # The .txt companion has the same stem
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
        fixture_id = json_path.stem.split("_")[0]  # e.g., "F-001"
        print(f"\n{'=' * 60}")
        print(f"Fixture: {json_path.name}")

        # Load annotation
        try:
            with open(json_path, encoding="utf-8") as f:
                annotation = json.load(f)
        except json.JSONDecodeError as e:
            print(f"  FAIL  [JSON parse error]: {e}")
            all_passed = False
            continue

        # Determine fixture text
        if txt_path is not None:
            try:
                with open(txt_path, encoding="utf-8") as f:
                    fixture_text = f.read()
            except OSError as e:
                print(f"  FAIL  [Cannot read .txt file]: {e}")
                all_passed = False
                continue
        else:
            # No .txt companion — use empty string (F-007 style, entities list should be absent or empty)
            fixture_text = ""
            entities = annotation.get("entities", [])
            if entities:
                print(
                    f"  WARN  No .txt companion file found but annotation has {len(entities)} entities. "
                    f"Span checks will fail. Is this a JSON-only fixture (like F-007)?"
                )

        # Run checks
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
```

---

## Part 4: Obfuscation Output Validation Rules

For any fixture run through the obfuscation pipeline, the following rules apply to the output:

**Rule OV-001:** Every `original_value` from every entity annotation must NOT appear in the obfuscated output text (case-insensitive).

**Rule OV-002:** The number of token patterns (`\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]`) in the obfuscated text must be ≥ the number of non-redacted entities (entities with `confidence ≥ 0.60`).

**Rule OV-003:** For each entity where `confidence < 0.60`, the string `[REDACTED]` must appear at the corresponding position.

**Rule OV-004:** For idempotency assertions: the number of unique tokens for a given original value must equal 1, not the count of occurrences.

**Rule OV-005:** Total character length of obfuscated text must be within ±50% of original text length (tokens are longer than short names but shorter than long addresses — average should be roughly comparable).

---

## Part 5: De-obfuscation Output Validation Rules

**Rule DV-001:** The `restored_text` must equal the `expected_output` from the F-007 test case (exact string match after stripping trailing whitespace).

**Rule DV-002:** `tokens_restored + tokens_missed` must equal the total number of token pattern matches found in the raw LLM response.

**Rule DV-003:** `restored_text` must not contain any token pattern matches (`\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]`) unless they are `[UNAVAILABLE]` (which is not a valid token pattern by the regex).

**Rule DV-004:** Any vault miss must produce exactly `[UNAVAILABLE]` in the output — not an empty string, not an exception, and not the original token string.

---

## Part 6: Golden Dataset File Structure

```
tests/
  fixtures/
    golden/
      F-001_medical_record_comprehensive.txt
      F-001_medical_record_comprehensive.json      # annotation
      F-002_legal_brief_privilege.txt
      F-002_legal_brief_privilege.json
      F-003_financial_disclosure.txt
      F-003_financial_disclosure.json
      F-004_clean_medical_guidance.txt
      F-004_clean_medical_guidance.json
      F-005_idempotency_stress.txt
      F-005_idempotency_stress.json
      F-006_low_confidence_entity.txt
      F-006_low_confidence_entity.json
      F-007_llm_response_deobfuscation.json       # no .txt — pre-built LLM responses
      F-008_multi_format_ssn.txt
      F-008_multi_format_ssn.json
      F-009_adjacent_entities.txt
      F-009_adjacent_entities.json
      validate_fixtures.py                         # Validation script (Rule G-003, etc.)
```

---

## Part 7: Adding New Fixtures

When adding a new fixture to the golden dataset, the contributor must:

1. Create the fixture text file with fully synthetic PII values.
2. Create the annotation JSON file following the schema in Rule G-002.
3. Run `python tests/fixtures/golden/validate_fixtures.py --fixture-dir tests/fixtures/golden` — all checks must pass.
4. Run the pipeline against the new fixture manually and verify the obfuscated output against Rules OV-001 through OV-005.
5. Submit the fixture + annotation + validation output as part of the PR.
6. Get sign-off from a second engineer before merging (four-eyes principle for sensitive test data).

---

*YourAI Confidential — Golden Dataset Rules v2.0 — Do not distribute*
