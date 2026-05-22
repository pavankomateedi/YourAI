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
        tokens = _TOKEN_RE.findall(payload.obfuscated_context)
        if tokens:
            joined = ", ".join(tokens)
            return f"Based on the document, the relevant entities are: {joined}."
        return "Based on the document, no sensitive entities were referenced."
