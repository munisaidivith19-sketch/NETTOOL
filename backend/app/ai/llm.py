"""Language-model providers, called with plain HTTPS requests (no vendor SDKs).

- gemini: Google AI Studio free tier      (LLM_API_KEY, sent in a header)
- groq:   Groq free tier, OpenAI-style API (LLM_API_KEY, Authorization header)
- ollama: a model running on this machine (no key; http://127.0.0.1:11434)
- none:   no model; NetMap uses its built-in question parser and template explanations

What goes in: only text that NetMap built on the server (a question plus a fixed schema, or
an alert/finding/diff with secrets removed). What comes out is treated as untrusted text:
queries are validated by query_guard, explanations are shown as plain text.
Errors are reported by type and status code only; response bodies are never logged.
"""

from __future__ import annotations

import logging
from typing import Protocol

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)
# httpx logs full request URLs at INFO; keep them out of the logs (Phase 5 rule).
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

DEFAULTS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta", "gemini-2.5-flash"),
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "ollama": ("http://127.0.0.1:11434", "llama3.2"),
}
MAX_OUTPUT_CHARS = 4000


class LLMError(Exception):
    """The model could not be used. The message is safe to show."""


class Provider(Protocol):
    name: str

    async def complete(self, system: str, user: str, max_tokens: int = 600) -> str: ...


class NoProvider:
    name = "none"

    async def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        raise LLMError("No language model is configured")


class _HttpProvider:
    name = "http"

    def __init__(self, settings: Settings) -> None:
        base, model = DEFAULTS[settings.llm_provider]
        self.base = (settings.llm_base_url or base).rstrip("/")
        self.model = settings.llm_model or model
        self.timeout = settings.llm_timeout_seconds
        self._key = settings.llm_api_key

    def _key_value(self) -> str:
        return self._key.get_secret_value() if self._key else ""

    async def _post(self, url: str, headers: dict, payload: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("%s request failed: %s", self.name, type(exc).__name__)
            raise LLMError("The language model did not answer") from None
        if response.status_code == 429:
            raise LLMError("The language model's free quota is used up; try again later")
        if response.status_code >= 400:
            logger.warning("%s returned HTTP %s", self.name, response.status_code)
            raise LLMError("The language model returned an error")
        try:
            return response.json()
        except ValueError:
            raise LLMError("The language model returned an unreadable answer") from None

    @staticmethod
    def _text(value) -> str:
        if not isinstance(value, str) or not value.strip():
            raise LLMError("The language model returned an empty answer")
        return value[:MAX_OUTPUT_CHARS]


class GeminiProvider(_HttpProvider):
    name = "gemini"

    async def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        data = await self._post(
            f"{self.base}/models/{self.model}:generateContent",
            {"x-goog-api-key": self._key_value()},
            {"systemInstruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": user}]}],
             "generationConfig": {"temperature": 0, "maxOutputTokens": max_tokens}})
        try:
            return self._text(data["candidates"][0]["content"]["parts"][0]["text"])
        except (KeyError, IndexError, TypeError):
            raise LLMError("The language model returned an unexpected answer") from None


class GroqProvider(_HttpProvider):
    name = "groq"

    async def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        data = await self._post(
            f"{self.base}/chat/completions",
            {"Authorization": f"Bearer {self._key_value()}"},
            {"model": self.model, "temperature": 0, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]})
        try:
            return self._text(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise LLMError("The language model returned an unexpected answer") from None


class OllamaProvider(_HttpProvider):
    name = "ollama"

    async def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        data = await self._post(
            f"{self.base}/api/chat", {},
            {"model": self.model, "stream": False,
             "options": {"temperature": 0, "num_predict": max_tokens},
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]})
        try:
            return self._text(data["message"]["content"])
        except (KeyError, TypeError):
            raise LLMError("The language model returned an unexpected answer") from None


def make_provider(settings: Settings) -> Provider:
    return {"gemini": GeminiProvider, "groq": GroqProvider,
            "ollama": OllamaProvider}.get(settings.llm_provider, lambda _s: NoProvider())(settings)
