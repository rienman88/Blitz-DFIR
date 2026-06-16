from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from blitz_dfir.exceptions import BlitzError
from blitz_dfir.reasoning.models import (
    LLMRequest,
    LLMResponse,
    ProviderMetadata,
    TokenUsage,
)


class ReasoningProviderError(BlitzError):
    pass


class LLMProvider(Protocol):
    def complete(self, request: LLMRequest) -> LLMResponse:
        ...


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    base_url: str
    api_key: str
    model: str


def provider_config_from_env() -> ProviderConfig:
    provider = os.getenv("LLM_PROVIDER", "openai-compatible")
    base_url = os.getenv("LLM_BASE_URL", "")
    api_key = os.getenv("LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "")
    if not base_url:
        raise ReasoningProviderError("LLM_BASE_URL is required")
    if not api_key:
        raise ReasoningProviderError("LLM_API_KEY is required")
    if not model:
        raise ReasoningProviderError("LLM_MODEL is required")
    return ProviderConfig(provider=provider, base_url=base_url, api_key=api_key, model=model)


class OpenAICompatibleProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    def complete(self, request: LLMRequest) -> LLMResponse:
        max_tokens = _provider_max_tokens(request.max_tokens)
        payload = {
            "model": request.model or self.config.model,
            "messages": [message.model_dump() for message in request.messages],
            "temperature": request.temperature,
            "max_tokens": max_tokens,
        }
        if _truthy_env("LLM_RESPONSE_FORMAT_JSON", default=False):
            payload["response_format"] = {"type": "json_object"}
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        url = _chat_completions_url(self.config.base_url)
        timeout_seconds = _provider_timeout_seconds()
        started = time.monotonic()
        http_request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "Blitz-DFIR/0.1 openai-compatible-client",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=timeout_seconds) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = _error_body_preview(exc)
            elapsed_seconds = time.monotonic() - started
            raise ReasoningProviderError(
                "LLM provider request failed: "
                f"HTTP {exc.code} {exc.reason}; "
                f"provider={self.config.provider}; "
                f"model={request.model or self.config.model}; "
                f"url={_safe_url(url)}; "
                f"timeout_seconds={timeout_seconds}; "
                f"elapsed_seconds={elapsed_seconds:.1f}; "
                f"max_tokens={max_tokens}; "
                f"body={body}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            elapsed_seconds = time.monotonic() - started
            raise ReasoningProviderError(
                "LLM provider request failed: "
                f"{exc}; "
                f"provider={self.config.provider}; "
                f"model={request.model or self.config.model}; "
                f"url={_safe_url(url)}; "
                f"timeout_seconds={timeout_seconds}; "
                f"elapsed_seconds={elapsed_seconds:.1f}; "
                f"max_tokens={max_tokens}"
            ) from exc

        choices = response_payload.get("choices") if isinstance(response_payload, dict) else None
        content = ""
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(message, dict):
                content = str(message.get("content", ""))
        usage = response_payload.get("usage") if isinstance(response_payload, dict) else None
        token_usage = None
        if isinstance(usage, dict):
            token_usage = TokenUsage(
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens"),
            )
        return LLMResponse(
            content=content,
            provider_metadata=ProviderMetadata(
                provider=self.config.provider,
                model=request.model or self.config.model,
                base_url=_safe_base_url(self.config.base_url),
                response_id=response_payload.get("id") if isinstance(response_payload, dict) else None,
            ),
            token_usage=token_usage,
        )


def default_provider_from_env() -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(provider_config_from_env())


def _chat_completions_url(base_url: str) -> str:
    clean = base_url.rstrip("/")
    if clean.endswith("/chat/completions"):
        return clean
    if clean.endswith("/v1"):
        return f"{clean}/chat/completions"
    return f"{clean}/v1/chat/completions"


def _safe_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return base_url.split("/")[0]


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return parsed.geturl()
    return url


def _provider_timeout_seconds() -> int:
    raw_value = os.getenv("LLM_TIMEOUT_SECONDS", "120")
    try:
        value = int(raw_value)
    except ValueError:
        raise ReasoningProviderError("LLM_TIMEOUT_SECONDS must be an integer") from None
    if value < 1 or value > 1800:
        raise ReasoningProviderError("LLM_TIMEOUT_SECONDS must be between 1 and 1800")
    return value


def _provider_max_tokens(default: int) -> int:
    raw_value = os.getenv("LLM_MAX_TOKENS", str(default))
    try:
        value = int(raw_value)
    except ValueError:
        raise ReasoningProviderError("LLM_MAX_TOKENS must be an integer") from None
    if value < 1 or value > 8000:
        raise ReasoningProviderError("LLM_MAX_TOKENS must be between 1 and 8000")
    return value


def _truthy_env(name: str, *, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _error_body_preview(exc: urllib.error.HTTPError, *, limit: int = 500) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except OSError:
        return "<unavailable>"
    normalized = " ".join(body.split())
    if not normalized:
        return "<empty>"
    if len(normalized) > limit:
        return f"{normalized[:limit]}..."
    return normalized
