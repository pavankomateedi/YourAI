"""Synthetic sample documents for the demo UI.

All content is **fabricated** — no real person, account, or institution. Names,
identifiers, drugs, and clauses are made up to exercise the detector across PII,
PHI, financial, and legal entity types. Stored as module constants so they ship
with the Python package (Docker ``COPY . .``) without extra packaging config.
"""

from __future__ import annotations

MEDICAL_RECORD = """\
ST. ELSEWHERE GENERAL — Internal Medicine
Patient Visit Summary — Confidential

Patient: John Smith
Date of birth: April 12, 1981
MRN-7293847
Address: 1450 Oakridge Lane, Cambridge, MA 02139
Phone: (415) 555-0182
Email: john.smith@example.com
Insurance ID: BCBS-99812341
SSN: 412-55-9981

Chief complaint:
Patient presents for routine follow-up of Type 2 Diabetes Mellitus, last reviewed
six months ago. Reports good adherence to medication; mild fatigue noted, no
hypoglycemic episodes.

Assessment:
- Type 2 Diabetes Mellitus, controlled
- Hyperlipidemia, on therapy

Plan:
- Continue Metformin 500mg PO BID with meals
- Atorvastatin 20mg PO QHS
- HbA1c: 7.8% (target < 7.0%)
- Repeat lipid panel in 3 months
- Schedule annual ophthalmology and podiatry exams

Signed,
Dr. Patricia Lee, MD
"""


LEGAL_CASE_SUMMARY = """\
LAW OFFICES OF CARTER & ASSOCIATES — Attorney Work Product
PRIVILEGED & CONFIDENTIAL — Do not distribute

Matter: Gonzalez v. Apex Industries, Inc.
Case No. CV-2025-04812
Lead attorney: Marcus Carter, Esq.

Client of record: Maria Gonzalez
Client SSN: 412-55-9981
Phone: (212) 555-0143
Email: maria.g@example.com
Address: 88 Beacon Street, Brooklyn, NY 11201

Background:
Client retained the firm on March 15 regarding the failed merger negotiations
with Apex Industries. Opposing counsel is Hartwell Pratt LLP. The dispute
centers on a non-compete clause and disputed share valuation.

Litigation strategy:
File motion for summary judgment before the 03/01/2026 deadline. Pursue
discovery on Apex's internal valuation memos. Reserve right to amend complaint
should the Q1 board minutes surface admissions of bad faith.

Settlement posture:
Client has authorized settlement up to $3.4M, contingent on a mutual release and
a 24-month non-disparagement clause.

Next actions:
1. Subpoena Apex board minutes (deadline: 02/14)
2. Depose former CFO Robert Tan
3. Engage forensic accountant for valuation challenge
"""


FINANCIAL_DISCLOSURE = """\
WEALTH ADVISORS GROUP — Client Financial Disclosure
CONFIDENTIAL — For internal review only

Account holder: Robert Tan
SSN: 123-45-6789
Date of birth: September 03, 1972
Address: 220 Maple Avenue, Palo Alto, CA 94301
Phone: (650) 555-0917
Email: robert.tan@example.com

Primary account: 4012-8888-8888-1881
Routing tax ID: 47-1234567
Insurance ID: AETNA-44218823

Disclosed income (2025): $487,500 — base salary, executive RSUs, and Q4 bonus
Liquid assets: approximately $1.2M across two brokerage accounts
Real estate: primary residence (Palo Alto), rental property (Tahoe)

Recent activity flagged for review:
- 11/28: wire transfer of $84,000 to settlement escrow account
- 12/03: investment of $250,000 into PRX Global Macro Fund
- 12/15: charitable contribution of $40,000 to Stanford Children's Hospital

Advisor notes:
Client requested rebalancing to a more conservative allocation following the
pending litigation. Recommend a 60/40 split with municipal-bond emphasis.

Advisor: Linda Pham, CFP
"""


SAMPLES: dict[str, tuple[str, str, str]] = {
    # id: (filename, mime, body)
    "medical": ("medical-record.txt", "text/plain", MEDICAL_RECORD),
    "legal": ("legal-case-summary.txt", "text/plain", LEGAL_CASE_SUMMARY),
    "financial": ("financial-disclosure.txt", "text/plain", FINANCIAL_DISCLOSURE),
}
