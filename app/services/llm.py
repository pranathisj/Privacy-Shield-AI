"""LLM providers. Every provider accepts sanitized text only."""

from __future__ import annotations

from typing import Protocol

import httpx

from app.config import Settings


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, sanitized_text: str) -> str: ...


class MockProvider:
    name = "mock"
    model = "local-mock"

    def complete(self, sanitized_text: str) -> str:
        return (
            "This is a local demo response. The AI received only this sanitized payload:\n\n"
            f"{sanitized_text}"
        )


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(self, settings: Settings) -> None:
        if settings.llm_api_key is None or not settings.llm_api_key.strip():
            raise ValueError("LLM_API_KEY is required for the openai-compatible provider.")
        self._settings = settings
        self._api_key = settings.llm_api_key.strip()
        self.model = settings.llm_model

    def complete(self, sanitized_text: str) -> str:
        payload = {
            "model": self._settings.llm_model,
            "messages": [
                {
                    "role": "system",
                    "content": "Answer the user's request. Any bracketed identifiers are redacted placeholders.",
                },
                {"role": "user", "content": sanitized_text},
            ],
        }
        try:
            response = httpx.post(
                f"{self._settings.llm_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=payload,
                timeout=self._settings.llm_timeout_seconds,
            )
            response.raise_for_status()
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("LLM provider returned an empty response.")
            return content
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError("LLM provider request failed.") from None


def create_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "mock":
        return MockProvider()
    if settings.llm_provider in {"openai", "openai-compatible"}:
        return OpenAICompatibleProvider(settings)
    raise ValueError(
        f"Unsupported LLM_PROVIDER '{settings.llm_provider}'. "
        "Choose 'mock' or 'openai-compatible'."
    )
