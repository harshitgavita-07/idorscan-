"""Pluggable LLM providers for the AI research assistant.

Providers: OpenAI, Anthropic (Claude), Google Gemini, local Ollama, and a
no-op ``NoneProvider`` default. All speak plain HTTPS via httpx — no heavy SDKs.

Guardrail baked into every prompt: the model must analyze ONLY the evidence we
supply, must never invent data, and may only use the word "confirmed" when the
supplied validation status already says CONFIRMED_IDOR.
"""
from __future__ import annotations

import json
from typing import Any, Protocol

import httpx

from bountygang.config import get_settings
from bountygang.logging_setup import get_logger

log = get_logger("ai")

SYSTEM_PROMPT = (
    "You are a careful bug bounty research assistant supporting an authorized "
    "IDOR/BOLA investigation. You will be given factual evidence captured by the "
    "tooling. Rules: (1) Never invent requests, responses, identifiers or data — "
    "reason strictly from the provided evidence. (2) Never describe a vulnerability "
    "as confirmed unless the evidence explicitly states validation_status="
    "CONFIRMED_IDOR; otherwise say 'suspected' or 'requires validation'. "
    "(3) Recommend only safe, in-policy validation steps using researcher-owned "
    "accounts/resources. (4) Point out likely false positives. Answer concisely."
)


class LLMProvider(Protocol):
    name: str

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        """Return assistant text, or None on any failure (AI is best-effort)."""
        ...


class NoneProvider:
    name = "none"

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        return None


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key, self.model = api_key, model

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        if not self.api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=60) as c:
                r = await c.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "max_tokens": max_tokens,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            log.warning("OpenAI call failed: %s", e)
            return None


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key, self.model = api_key, model

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        if not self.api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=60) as c:
                r = await c.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                    json={
                        "model": self.model,
                        "max_tokens": max_tokens,
                        "system": SYSTEM_PROMPT,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                r.raise_for_status()
                parts = r.json().get("content", [])
                return "".join(p.get("text", "") for p in parts) or None
        except Exception as e:
            log.warning("Anthropic call failed: %s", e)
            return None


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key, self.model = api_key, model

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        if not self.api_key:
            return None
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=60) as c:
                r = await c.post(url, params={"key": self.api_key},
                                 json={"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                                       "contents": [{"role": "user",
                                                     "parts": [{"text": prompt}]}],
                                       "generationConfig": {"maxOutputTokens": max_tokens}})
                r.raise_for_status()
                data = r.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            log.warning("Gemini call failed: %s", e)
            return None


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str) -> None:
        self.base_url, self.model = base_url.rstrip("/"), model

    async def complete(self, prompt: str, *, max_tokens: int = 800) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                r = await c.post(f"{self.base_url}/api/chat",
                                 json={"model": self.model, "stream": False,
                                       "messages": [
                                           {"role": "system", "content": SYSTEM_PROMPT},
                                           {"role": "user", "content": prompt}],
                                       "options": {"num_predict": max_tokens}})
                r.raise_for_status()
                return r.json().get("message", {}).get("content")
        except Exception as e:
            log.info("Ollama unavailable (%s): %s", self.base_url, e)
            return None


def make_provider(settings=None) -> LLMProvider:
    s = settings or get_settings()
    p = (s.llm_provider or "none").lower()
    if p == "openai":
        return OpenAIProvider(s.openai_api_key, s.openai_model)
    if p in ("anthropic", "claude"):
        return AnthropicProvider(s.anthropic_api_key, s.anthropic_model)
    if p in ("gemini", "google"):
        return GeminiProvider(s.gemini_api_key, s.gemini_model)
    if p == "ollama":
        return OllamaProvider(s.ollama_base_url, s.ollama_model)
    return NoneProvider()


def build_endpoint_prompt(host: str, path: str, method: str, evidence: dict[str, Any]) -> str:
    return (
        f"Analyze this endpoint for potential BOLA/IDOR risk within an authorized "
        f"bug bounty scope.\nEndpoint: {method} https://{host}{path}\n"
        f"Captured evidence (sanitized):\n{json.dumps(evidence, indent=1)[:6000]}\n\n"
        f"Provide: 1) why it is or is not suspicious, 2) missing authorization checks to "
        f"test, 3) SAFE validation steps using only researcher-owned accounts/test data, "
        f"4) false-positive reasons. Do not claim confirmation unless evidence says so."
    )


def build_report_prompt(title: str, context: dict[str, Any]) -> str:
    return (
        "Draft the DESCRIPTION / IMPACT / REMEDIATION sections of a HackerOne-style "
        "report from EXACTLY this evidence (do not add facts):\n"
        f"{json.dumps(context, indent=1)[:8000]}"
    )
