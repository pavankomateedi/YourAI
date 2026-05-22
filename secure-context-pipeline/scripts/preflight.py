#!/usr/bin/env python3
"""Production preflight — verify the service is safe to launch.

Checks the hard requirements for a production deployment and runs a live
self-test (detect -> obfuscate -> leak gate -> restore) end to end. Exits non-zero
if any hard requirement fails, so it can gate a deploy.

    SCP_ENV=production python scripts/preflight.py
"""

from __future__ import annotations

import asyncio
import os
import sys

GREEN, RED, YEL, RST = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def _ok(msg): print(f"{GREEN}  PASS{RST}  {msg}")
def _fail(msg): print(f"{RED}  FAIL{RST}  {msg}")
def _warn(msg): print(f"{YEL}  WARN{RST}  {msg}")


async def main() -> int:
    is_prod = os.environ.get("SCP_ENV", "development").lower() in {"production", "prod"}
    hard_failures = 0
    print(f"Preflight (SCP_ENV={os.environ.get('SCP_ENV', 'development')})\n" + "-" * 50)

    # 1. Master key provisioning (fails closed in prod without a persistent key).
    try:
        from secure_context_pipeline.security.keys import MasterKeyProvider

        key = MasterKeyProvider().get_master_key()
        assert len(key) == 32
        _ok("master key provisioned (32 bytes)")
    except Exception as e:
        _fail(f"master key: {e}")
        hard_failures += 1

    # 2. Service API key set (auth enforced).
    if os.environ.get("SERVICE_API_KEY"):
        _ok("SERVICE_API_KEY set (X-API-Key auth enforced)")
    elif is_prod:
        _fail("SERVICE_API_KEY missing — service would be unauthenticated")
        hard_failures += 1
    else:
        _warn("SERVICE_API_KEY not set (dev) — auth disabled")

    # 3. Vault backend.
    backend = os.environ.get("VAULT_BACKEND", "sqlite").lower()
    if backend == "postgres":
        if not os.environ.get("DATABASE_URL"):
            _fail("VAULT_BACKEND=postgres but DATABASE_URL missing")
            hard_failures += 1
        else:
            try:
                import asyncpg  # noqa: F401
                _ok("postgres backend configured (asyncpg available)")
            except Exception:
                _fail("asyncpg not installed (pip install .[postgres])")
                hard_failures += 1
    elif is_prod:
        _warn("VAULT_BACKEND=sqlite in production — prefer postgres for HA")
    else:
        _ok("vault backend: sqlite (dev)")

    # 4. Key wrapping.
    wrapping = os.environ.get("KEY_WRAPPING", "none").lower()
    if wrapping == "none" and is_prod:
        _warn("KEY_WRAPPING=none in production — prefer local (KEK) or kms")
    else:
        _ok(f"key wrapping: {wrapping}")

    # 5. LLM backend.
    if os.environ.get("ANTHROPIC_API_KEY"):
        _ok("ANTHROPIC_API_KEY set (live Claude)")
    else:
        _warn("no ANTHROPIC_API_KEY — pipeline will use the offline echo-mock")

    # 6. Live self-test: a known identifier must not survive into the payload.
    try:
        from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline

        captured = {}

        async def capture(ctx, q):
            captured["ctx"] = ctx
            return ctx  # echo so restoration is exercised

        pipe = SecureContextPipeline(llm_fn=capture)
        result = await pipe.run(
            user_id="preflight", session_id="preflight-session",
            text="Patient SSN 543-67-8901, email probe@example.com.",
            user_query="check",
        )
        leaked = "543-67-8901" in captured.get("ctx", "") or "probe@example.com" in captured.get("ctx", "")
        if leaked:
            _fail("self-test: raw identifier leaked into outbound payload")
            hard_failures += 1
        elif result.entities_detected >= 2 and "543-67-8901" in result.restored_response:
            _ok("self-test: detect -> obfuscate -> restore round trip clean")
        else:
            _fail("self-test: round trip did not restore expected values")
            hard_failures += 1
    except Exception as e:
        _fail(f"self-test errored: {e}")
        hard_failures += 1

    print("-" * 50)
    if hard_failures == 0:
        print(f"{GREEN}READY TO DEPLOY{RST}")
        return 0
    print(f"{RED}NOT READY — {hard_failures} hard failure(s){RST}")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
