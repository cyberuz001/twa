from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx


class FailureKind(StrEnum):
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    CONTEXT_LENGTH_EXCEEDED = "CONTEXT_LENGTH_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    NETWORK_ERROR = "NETWORK_ERROR"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_CONTENT_FILTER = "PROVIDER_CONTENT_FILTER"
    MODEL_REFUSAL = "MODEL_REFUSAL"
    INVALID_TOOL_CALL = "INVALID_TOOL_CALL"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class ProviderFailure(Exception):
    kind: FailureKind
    message: str
    retryable: bool = False

    def __str__(self) -> str:
        return f"{self.kind.value}: {self.message}"


def classify_failure(status: int | None = None, message: str = "", code: str = "") -> FailureKind:
    sample = f"{message} {code}".lower()
    if any(
        x in sample
        for x in ("content_filter", "content filter", "safety_violation", "blocked by safety")
    ):
        return FailureKind.PROVIDER_CONTENT_FILTER
    if any(
        x in sample
        for x in ("refus", "cannot help with", "can't assist with", "not able to assist")
    ):
        return FailureKind.MODEL_REFUSAL
    if any(
        x in sample
        for x in ("context_length", "maximum context", "too many tokens", "context window")
    ):
        return FailureKind.CONTEXT_LENGTH_EXCEEDED
    if status == 429 or any(x in sample for x in ("rate_limit", "rate limit", "too many requests")):
        return FailureKind.RATE_LIMITED
    if status in (408, 504) or "timeout" in sample:
        return FailureKind.PROVIDER_TIMEOUT
    if status == 404 or any(
        x in sample for x in ("model_not_found", "model unavailable", "unknown model")
    ):
        return FailureKind.MODEL_UNAVAILABLE
    if status in (401, 403) or any(
        x in sample for x in ("unauthorized", "invalid api key", "authentication")
    ):
        return FailureKind.AUTHENTICATION_ERROR
    if any(x in sample for x in ("tool_call", "tool call", "function call")):
        return FailureKind.INVALID_TOOL_CALL
    if status is not None and status >= 500:
        return FailureKind.NETWORK_ERROR
    return FailureKind.UNKNOWN_ERROR


class ModelResponseRecoveryEngine:
    """Classifies provider failures and retries only bounded transient errors."""

    def __init__(self, max_retries: int = 2, base_delay: float = 0.15):
        self.max_retries = max(0, min(max_retries, 5))
        self.base_delay = max(0.0, min(base_delay, 2.0))

    def run(self, operation: Any, on_recovery: Any = None, compact_operation: Any = None) -> str:
        compacted = False
        for attempt in range(self.max_retries + 1):
            try:
                result = operation()
                if not isinstance(result, str) or not result.strip():
                    raise ProviderFailure(
                        FailureKind.MALFORMED_RESPONSE, "Provider returned no text"
                    )
                if looks_like_refusal(result):
                    raise ProviderFailure(FailureKind.MODEL_REFUSAL, result[:240])
                return result
            except ProviderFailure as failure:
                if on_recovery:
                    on_recovery(failure, attempt)
                if (
                    failure.kind == FailureKind.CONTEXT_LENGTH_EXCEEDED
                    and compact_operation is not None
                    and not compacted
                ):
                    compacted = True
                    try:
                        compact_result = compact_operation()
                        if not isinstance(compact_result, str) or not compact_result.strip():
                            raise ProviderFailure(
                                FailureKind.MALFORMED_RESPONSE,
                                "Compact evidence request returned no text",
                            )
                        if looks_like_refusal(compact_result):
                            raise ProviderFailure(FailureKind.MODEL_REFUSAL, compact_result[:240])
                        return compact_result
                    except ProviderFailure as compact_failure:
                        if on_recovery:
                            on_recovery(compact_failure, attempt + 1)
                        raise compact_failure
                if failure.retryable and attempt < self.max_retries:
                    time.sleep(self.base_delay * (2**attempt))
                    continue
                raise
            except httpx.TimeoutException as exc:
                failure = ProviderFailure(FailureKind.PROVIDER_TIMEOUT, str(exc)[:240], True)
                if on_recovery:
                    on_recovery(failure, attempt)
                if attempt < self.max_retries:
                    time.sleep(self.base_delay * (2**attempt))
                    continue
                raise failure from exc
            except httpx.NetworkError as exc:
                failure = ProviderFailure(FailureKind.NETWORK_ERROR, str(exc)[:240], True)
                if on_recovery:
                    on_recovery(failure, attempt)
                if attempt < self.max_retries:
                    time.sleep(self.base_delay * (2**attempt))
                    continue
                raise failure from exc


def looks_like_refusal(text: str) -> bool:
    pattern = (
        r"\b(I (?:cannot|can't|won't) (?:help|assist|provide)|I am unable to assist|"
        r"request (?:is|seems) (?:unsafe|disallowed))\b"
    )
    return bool(re.search(pattern, text, re.I))


def _omniroute_command(*args: str, timeout: int = 25) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("omniroute")
    if not executable:
        raise RuntimeError("OmniRoute CLI is not installed")
    try:
        return subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"OmniRoute command timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"OmniRoute CLI could not be started: {exc}") from exc


def omniroute_version() -> str | None:
    if not shutil.which("omniroute"):
        return None
    try:
        result = _omniroute_command("--version", timeout=5)
    except (RuntimeError, TimeoutError):
        return None
    return (
        result.stdout.strip().splitlines()[-1]
        if result.returncode == 0 and result.stdout.strip()
        else None
    )


def should_skip_browser() -> bool:
    return sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    )


def start_antigravity_login(no_browser: bool = False) -> tuple[bool, str]:
    executable = shutil.which("omniroute")
    if not executable:
        raise RuntimeError("OmniRoute CLI is not installed")
    command = [executable, "oauth", "start", "--provider", "antigravity"]
    if no_browser:
        command.append("--no-browser")
    # Inherit the terminal so OmniRoute's authorization URL and live prompts
    # remain visible while the callback server is waiting for the user.
    try:
        result = subprocess.run(command, timeout=310, check=False, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Antigravity login timed out before OmniRoute confirmed sign-in"
        ) from exc
    return result.returncode == 0, ""


def revoke_antigravity() -> tuple[bool, str]:
    result = _omniroute_command("oauth", "revoke", "--provider", "antigravity", "--yes")
    return result.returncode == 0, (result.stdout + result.stderr)[-1000:]


def antigravity_status() -> str:
    if not shutil.which("omniroute"):
        return "OmniRoute CLI not installed"
    result = _omniroute_command("oauth", "status", "--provider", "antigravity")
    output = result.stdout + result.stderr
    if result.returncode:
        return "STATUS_UNAVAILABLE"
    if re.search(r"\b(connected|authenticated|active)\b", output, re.I):
        return "AUTHENTICATED"
    if re.search(r"no (?:active )?(?:oauth )?connections|not connected|none found", output, re.I):
        return "NOT_CONNECTED"
    return "STATUS_UNAVAILABLE"


def discover_models(timeout: int = 25) -> list[dict[str, str]]:
    result = _omniroute_command("models", "--json", timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Model discovery failed")[-1000:])
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OmniRoute returned malformed model JSON") from exc
    items = (
        payload
        if isinstance(payload, list)
        else payload.get("data", payload.get("models", []))
        if isinstance(payload, dict)
        else []
    )
    models = []
    for item in items:
        if isinstance(item, str):
            models.append({"id": item, "name": item})
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            models.append({"id": item["id"], "name": str(item.get("name") or item["id"])})
    return models


def preferred_model(models: list[dict[str, str]]) -> str | None:
    for model in models:
        if re.search(r"opus", model["id"] + " " + model["name"], re.I):
            return model["id"]
    return None


class OmniRouteClient:
    def __init__(
        self, base_url: str | None = None, api_key: str | None = None, timeout: float = 45
    ):
        self.base_url = (base_url or os.getenv("OMNIROUTE_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("OMNIROUTE_API_KEY")
        self.timeout = timeout
        if self.base_url.endswith("/v1"):
            self.base_url = self.base_url[:-3]

    def chat(self, model: str, prompt: str) -> str:
        if not self.base_url:
            raise ProviderFailure(FailureKind.NETWORK_ERROR, "OMNIROUTE_BASE_URL is not configured")
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            response = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                },
                timeout=self.timeout,
            )
        except httpx.TimeoutException as exc:
            raise ProviderFailure(FailureKind.PROVIDER_TIMEOUT, str(exc)[:240], True) from exc
        except httpx.NetworkError as exc:
            raise ProviderFailure(FailureKind.NETWORK_ERROR, str(exc)[:240], True) from exc
        if response.is_error:
            try:
                payload = response.json()
                err = payload.get("error", {})
                message = str(err.get("message", payload)) if isinstance(err, dict) else str(err)
                code = str(err.get("code", "")) if isinstance(err, dict) else ""
            except ValueError:
                message, code = response.text[:500], ""
            kind = classify_failure(response.status_code, message, code)
            raise ProviderFailure(
                kind,
                message[:500],
                kind == FailureKind.RATE_LIMITED
                or kind == FailureKind.NETWORK_ERROR
                or kind == FailureKind.PROVIDER_TIMEOUT,
            )
        try:
            payload = response.json()
            text = payload["choices"][0]["message"]["content"]
            if isinstance(text, list):
                text = "".join(item.get("text", "") for item in text if isinstance(item, dict))
            if not isinstance(text, str):
                raise TypeError("message content is not text")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderFailure(
                FailureKind.MALFORMED_RESPONSE, "Malformed OpenAI-compatible chat response"
            ) from exc
        if payload["choices"][0].get("finish_reason") == "content_filter":
            raise ProviderFailure(
                FailureKind.PROVIDER_CONTENT_FILTER, "Provider marked response as content-filtered"
            )
        return text
