"""LLM Context Injector — assemble the obfuscated payload and call the provider.

The system prompt and the obfuscated document are kept separate, and the prompt
instructs the model to echo tokens/pseudonyms verbatim so de-obfuscation can
restore them. The real Anthropic Claude API is the primary backend; when no API
key is configured (or the SDK is unavailable) a deterministic echo mock is used so
the pipeline runs fully offline (NFR-2 resilience). All tests inject their own
``llm_fn`` and never reach a real network call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import get_settings
from ..models import LLMResponse

_SYSTEM_PROMPT = (
    "You are a helpful AI assistant. The document you are given has been processed "
    "for privacy: some values have been replaced with tokens like [PII_NAME_xxxxxxxx] "
    "or with realistic pseudonyms. When you refer to these entities in your response, "
    "reproduce the exact token or pseudonym as given. Do not guess, expand, or "
    "reconstruct any original value."
)

_TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9a-fA-F]{8}\]")


@dataclass
class LLMContextPayload:
    system_prompt: str
    obfuscated_context: str
    user_query: str
    session_id: str


class LLMContextInjector:
    def __init__(self, provider: str | None = None) -> None:
        self._settings = get_settings()
        self._provider = provider or self._settings.llm_provider

    async def build_payload(self, obfuscated_doc, user_query: str, session_id: str) -> LLMContextPayload:
        context = getattr(obfuscated_doc, "obfuscated_text", str(obfuscated_doc))
        return LLMContextPayload(
            system_prompt=_SYSTEM_PROMPT,
            obfuscated_context=context,
            user_query=user_query,
            session_id=session_id,
        )

    async def call_llm(self, payload: LLMContextPayload, provider: str | None = None) -> LLMResponse:
        provider = provider or self._provider
        user_content = (
            f"Document:\n{payload.obfuscated_context}\n\nQuestion: {payload.user_query}"
        )

        if provider == "anthropic" and self._settings.anthropic_api_key:
            text, usage = await self._call_anthropic(payload, user_content)
            return LLMResponse(text, "anthropic", self._settings.llm_model, usage, payload.session_id)
        if provider == "openai" and self._settings.openai_api_key:
            text, usage = await self._call_openai(payload, user_content)
            return LLMResponse(text, "openai", self._settings.llm_model, usage, payload.session_id)

        # Offline deterministic fallback: echo the tokens so the round-trip is visible.
        return LLMResponse(self._mock_response(payload), "mock", "echo-mock", {}, payload.session_id)

    async def _call_anthropic(self, payload: LLMContextPayload, user_content: str):
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._settings.anthropic_api_key)
        message = await client.messages.create(
            model=self._settings.llm_model,
            max_tokens=1024,
            system=payload.system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(getattr(b, "text", "") for b in message.content)
        usage = {
            "input_tokens": getattr(message.usage, "input_tokens", 0),
            "output_tokens": getattr(message.usage, "output_tokens", 0),
        }
        return text, usage

    async def _call_openai(self, payload: LLMContextPayload, user_content: str):
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self._settings.openai_api_key)
        resp = await client.chat.completions.create(
            model=self._settings.llm_model,
            messages=[
                {"role": "system", "content": payload.system_prompt},
                {"role": "user", "content": user_content},
            ],
        )
        return resp.choices[0].message.content or "", {}

    @staticmethod
    def _mock_response(payload: LLMContextPayload) -> str:
        """Deterministic, entity-aware templated summary.

        Real Claude generates the natural-language summary in production. With no
        API key set, this mock infers the document genre from the token mix
        (medical / legal / financial / mixed) and emits a plausible summary that
        embeds the bracketed tokens — so de-obfuscation can still restore them to
        real values and the demo's restored panel reads like a real summary."""
        text = payload.obfuscated_context or ""
        # Group bracketed tokens by their type prefix (e.g. ``PHI_MRN``) while
        # preserving first-seen order within each type.
        by_type: dict[str, list[str]] = {}
        seen: set[str] = set()
        for m in _TOKEN_RE.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            seen.add(tok)
            inner = tok[1:-1]
            parts = inner.split("_")
            prefix = "_".join(parts[:2]) if len(parts) >= 3 else parts[0]
            by_type.setdefault(prefix, []).append(tok)

        if not by_type:
            return ("Looking at the document, I see no sensitive identifiers or "
                    "personal information to flag. The content reads as a general "
                    "summary with no individual records.")

        name = (by_type.get("PII_NAME") or [None])[0]
        has_phi = any(k.startswith("PHI_") for k in by_type)
        has_legal = any(k.startswith("LEG_") for k in by_type)
        has_financial = any(k in by_type for k in ("FIN_ACCOUNT", "FIN_TAX_ID"))

        out: list[str] = []
        if has_phi:
            who = f" for {name}" if name else ""
            out.append(f"This appears to be a medical record{who}.")
            if "PHI_DIAGNOSIS" in by_type:
                out.append(
                    f"The patient's documented condition is {', '.join(by_type['PHI_DIAGNOSIS'])}."
                )
            if "PHI_MEDICATION" in by_type:
                out.append(
                    f"Prescribed medications include {', '.join(by_type['PHI_MEDICATION'])}."
                )
            if "PHI_LAB_RESULT" in by_type:
                out.append(
                    f"Recent lab results on file: {', '.join(by_type['PHI_LAB_RESULT'])}."
                )
            if "PHI_MRN" in by_type:
                out.append(f"Medical record number on file: {by_type['PHI_MRN'][0]}.")
            if "PHI_INSURANCE_ID" in by_type:
                out.append(f"Insurance reference: {by_type['PHI_INSURANCE_ID'][0]}.")
        elif has_legal:
            who = f" involving {name}" if name else ""
            out.append(f"This is a legal matter{who}.")
            if "LEG_CLIENT" in by_type:
                out.append(f"Client of record: {by_type['LEG_CLIENT'][0]}.")
            if "LEG_STRATEGY" in by_type:
                out.append(f"Litigation strategy noted: {by_type['LEG_STRATEGY'][0]}.")
        elif has_financial:
            who = f" for {name}" if name else ""
            out.append(f"This is a financial disclosure{who}.")
            if "FIN_ACCOUNT" in by_type:
                out.append(f"Primary account referenced: {by_type['FIN_ACCOUNT'][0]}.")
            if "FIN_TAX_ID" in by_type:
                out.append(f"Tax identifier on file: {by_type['FIN_TAX_ID'][0]}.")
        else:
            who = f"about {name}" if name else "with personal information"
            out.append(f"The document is {who}.")

        # Identity + contact addenda — useful in every genre when present.
        if "PII_SSN" in by_type:
            out.append(f"Identity number referenced: {by_type['PII_SSN'][0]}.")
        if "PII_DOB" in by_type:
            out.append(f"Date of birth: {by_type['PII_DOB'][0]}.")
        contacts = (by_type.get("PII_EMAIL", []) + by_type.get("PII_PHONE", []))[:2]
        if contacts:
            out.append(f"Contact details listed: {', '.join(contacts)}.")
        if "PII_ADDRESS" in by_type:
            out.append(f"Address on file: {by_type['PII_ADDRESS'][0]}.")
        return " ".join(out)
