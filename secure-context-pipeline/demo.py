#!/usr/bin/env python3
"""End-to-end demo of the Secure Context Pipeline.

Runs the full round trip on a bundled medical-record fixture:

    detect -> obfuscate -> [leak gate] -> call LLM -> de-obfuscate -> restore

If ``ANTHROPIC_API_KEY`` is set in the environment / ``.env`` the real Claude API
is called; otherwise a deterministic offline echo-mock stands in so the demo runs
anywhere. The vault is destroyed at the end, after which the mappings are gone.

    python demo.py
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

from secure_context_pipeline.audit.audit_log import AuditLog
from secure_context_pipeline.config import get_settings
from secure_context_pipeline.detection.detector import PIIDetector
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
from secure_context_pipeline.models import REQUIRED_ENTITY_TYPES
from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
from secure_context_pipeline.vault.vault import SessionVault

FIXTURE = Path(__file__).parent / "tests" / "fixtures" / "golden" / "F-001_medical_record_comprehensive.txt"
RULE = "=" * 72


def banner(title: str) -> None:
    print(f"\n{RULE}\n  {title}\n{RULE}")


async def main() -> None:
    settings = get_settings()
    text = FIXTURE.read_text(encoding="utf-8")
    user_id = f"demo-user-{uuid.uuid4().hex[:6]}"
    session_id = f"demo-session-{uuid.uuid4().hex[:8]}"
    audit = AuditLog(log_path=os.path.join("data", "demo_audit.jsonl"))

    backend = "Anthropic Claude (live)" if settings.anthropic_api_key else "offline echo-mock"
    banner("SECURE CONTEXT PIPELINE — DEMO")
    print(f"LLM backend: {backend}    model: {settings.llm_model}")

    banner("1. ORIGINAL DOCUMENT (never leaves YourAI in this form)")
    print(text)

    # Show the obfuscation step explicitly so the demo is legible.
    detector = PIIDetector()
    vault = SessionVault(db_path=os.path.join("data", "demo_vault.db"))
    engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})
    entities = await detector.detect(text)
    obf = await engine.obfuscate_document(text, entities, vault, session_id)

    banner(f"2. DETECTED {len(entities)} ENTITIES")
    for e in sorted(entities, key=lambda x: x.start):
        print(f"  {e.entity_type:<18} conf={e.confidence:.2f}  {e.original_value!r}")

    banner("3. OBFUSCATED PAYLOAD (this is what crosses the trust boundary)")
    print(obf.obfuscated_text)
    await vault.destroy(session_id)

    # Full pipeline run (its own internal vault) for the restored answer.
    pipeline = SecureContextPipeline(audit_log=audit)
    result = await pipeline.run(
        user_id=user_id,
        session_id=session_id,
        text=text,
        user_query="Summarize this patient's record and current treatment.",
    )

    banner("4. RESTORED RESPONSE (returned to the user, originals re-inserted)")
    print(result.restored_response)

    banner("5. PIPELINE METRICS")
    print(f"  entities detected:   {result.entities_detected}")
    print(f"  entities obfuscated: {result.entities_obfuscated}")
    print(f"  tokens restored:     {result.tokens_restored}")
    print(f"  duration:            {result.pipeline_duration_ms:.1f} ms")

    await pipeline.destroy_session(session_id, user_id=user_id)
    banner("6. SESSION DESTROYED — vault mappings are now irrecoverable")
    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
