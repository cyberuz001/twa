from __future__ import annotations

import httpx
import pytest

import twa.providers as providers
from twa.providers import (
    FailureKind,
    ModelResponseRecoveryEngine,
    ProviderFailure,
    classify_failure,
    preferred_model,
)


def test_failure_classification_filter_vs_refusal():
    assert classify_failure(400, "content_filter") == FailureKind.PROVIDER_CONTENT_FILTER
    assert classify_failure(200, "I cannot help with that request") == FailureKind.MODEL_REFUSAL


def test_transient_429_retried_then_success():
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ProviderFailure(FailureKind.RATE_LIMITED, "429", True)
        return "local evidence indicates a likely path"

    engine = ModelResponseRecoveryEngine(max_retries=2, base_delay=0)
    assert engine.run(operation) == "local evidence indicates a likely path"
    assert calls == 3


def test_refusal_not_retried_and_diagnostic_preserved():
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        return "I cannot help with that request"

    with pytest.raises(ProviderFailure) as error:
        ModelResponseRecoveryEngine(max_retries=4).run(operation)
    assert error.value.kind == FailureKind.MODEL_REFUSAL
    assert calls == 1


def test_content_filter_response_category_not_refusal():
    assert (
        classify_failure(None, "safety_violation: blocked by safety")
        == FailureKind.PROVIDER_CONTENT_FILTER
    )
    assert (
        classify_failure(403, "request blocked by content_filter")
        == FailureKind.PROVIDER_CONTENT_FILTER
    )


def test_malformed_tool_response_not_called_success():
    with pytest.raises(ProviderFailure) as error:
        ModelResponseRecoveryEngine().run(lambda: "")
    assert error.value.kind == FailureKind.MALFORMED_RESPONSE


def test_network_failure_retries_bounded():
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("offline")

    with pytest.raises(ProviderFailure) as error:
        ModelResponseRecoveryEngine(max_retries=1, base_delay=0).run(operation)
    assert error.value.kind == FailureKind.NETWORK_ERROR
    assert calls == 2


def test_prefers_only_present_opus_model():
    models = [
        {"id": "gemini/pro", "name": "Gemini Pro"},
        {"id": "antigravity/opus", "name": "Claude Opus"},
    ]
    assert preferred_model(models) == "antigravity/opus"
    assert preferred_model(models[:1]) is None


def test_oversized_context_uses_one_compact_request():
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        raise ProviderFailure(FailureKind.CONTEXT_LENGTH_EXCEEDED, "too many tokens")

    result = ModelResponseRecoveryEngine().run(operation, compact_operation=lambda: "compact notes")
    assert result == "compact notes"
    assert calls == 1


def test_headless_linux_skips_browser(monkeypatch):
    monkeypatch.setattr(providers.sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert providers.should_skip_browser()
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    assert not providers.should_skip_browser()


def test_antigravity_login_streams_and_supports_no_browser(monkeypatch):
    monkeypatch.setattr(providers.shutil, "which", lambda _: "/usr/bin/omniroute")
    seen = {}

    def run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return providers.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(providers.subprocess, "run", run)
    assert providers.start_antigravity_login(no_browser=True) == (True, "")
    assert seen["command"][-1] == "--no-browser"
    assert seen["kwargs"]["shell"] is False
    assert "capture_output" not in seen["kwargs"]


def test_hung_or_invalid_omniroute_cli_fails_fast(monkeypatch):
    monkeypatch.setattr(providers.shutil, "which", lambda _: "/mnt/c/windows-omniroute")
    monkeypatch.setattr(
        providers,
        "_omniroute_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    assert providers.omniroute_version() is None
