from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .core import workspace_root


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    application: dict[str, Any] = Field(default_factory=lambda: {"default_silent": True})
    ai: dict[str, Any] = Field(
        default_factory=lambda: {"preferred_model_family": "opus", "model": None}
    )
    agent: dict[str, Any] = Field(
        default_factory=lambda: {"max_steps": 10, "max_retries": 2, "timeout": 90}
    )
    recovery: dict[str, Any] = Field(
        default_factory=lambda: {
            "enabled": True,
            "retry_transient_errors": True,
            "continue_local_analysis": True,
        }
    )
    security: dict[str, Any] = Field(
        default_factory=lambda: {
            "scope_confirmation": "required",
            "network_rate_limit": 2,
            "preserve_original_files": True,
        }
    )
    reporting: dict[str, Any] = Field(
        default_factory=lambda: {"save_json": True, "redact_credentials": True}
    )

    @field_validator("application")
    @classmethod
    def validate_application(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(value, {"name", "default_silent"})
        if "default_silent" in value and not isinstance(value["default_silent"], bool):
            raise ValueError("application.default_silent must be boolean")
        return value

    @field_validator("ai")
    @classmethod
    def validate_ai(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(
            value,
            {
                "gateway",
                "provider",
                "preferred_model_family",
                "model",
                "allow_model_selection",
                "allow_automatic_fallback",
            },
        )
        for key in ("allow_model_selection", "allow_automatic_fallback"):
            if key in value and not isinstance(value[key], bool):
                raise ValueError(f"ai.{key} must be boolean")
        for key in ("gateway", "provider", "preferred_model_family", "model"):
            if key in value and value[key] is not None and not isinstance(value[key], str):
                raise ValueError(f"ai.{key} must be text")
        return value

    @field_validator("agent")
    @classmethod
    def validate_agent(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(
            value, {"autonomous", "max_steps", "max_retries", "timeout", "save_sessions"}
        )
        for key in ("autonomous", "save_sessions"):
            if key in value and not isinstance(value[key], bool):
                raise ValueError(f"agent.{key} must be boolean")
        _validate_range(value, "max_steps", 1, 50)
        _validate_range(value, "max_retries", 0, 5)
        _validate_range(value, "timeout", 1, 3600)
        return value

    @field_validator("recovery")
    @classmethod
    def validate_recovery(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(
            value,
            {
                "enabled",
                "classify_refusals",
                "preserve_evidence",
                "retry_transient_errors",
                "continue_local_analysis",
            },
        )
        _validate_booleans(value, "recovery")
        return value

    @field_validator("security")
    @classmethod
    def validate_security(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(
            value,
            {
                "scope_confirmation",
                "network_rate_limit",
                "sandbox_required_for_untrusted_execution",
                "preserve_original_files",
            },
        )
        _validate_range(value, "network_rate_limit", 1, 100)
        _validate_booleans(value, "security", exclude={"scope_confirmation", "network_rate_limit"})
        if "scope_confirmation" in value and value["scope_confirmation"] not in {
            "required",
            "disabled",
        }:
            raise ValueError("security.scope_confirmation must be 'required' or 'disabled'")
        return value

    @field_validator("reporting")
    @classmethod
    def validate_reporting(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_section(value, {"save_json", "redact_credentials"})
        _validate_booleans(value, "reporting")
        return value


def _validate_section(value: dict[str, Any], allowed: set[str]) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        raise ValueError(f"Unknown configuration key(s): {', '.join(sorted(unexpected))}")


def _validate_range(value: dict[str, Any], key: str, minimum: int, maximum: int) -> None:
    if key not in value:
        return
    selected = value[key]
    if isinstance(selected, bool) or not isinstance(selected, (int, float)):
        raise ValueError(f"{key} must be a number")
    if not minimum <= selected <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")


def _validate_booleans(
    value: dict[str, Any], section: str, exclude: set[str] | None = None
) -> None:
    for key, selected in value.items():
        if key not in (exclude or set()) and not isinstance(selected, bool):
            raise ValueError(f"{section}.{key} must be boolean")


def config_path(root: Path | None = None) -> Path:
    return (root or workspace_root()) / "config.yaml"


def load_config(root: Path | None = None) -> Config:
    path = config_path(root)
    if not path.exists():
        return Config()
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("Configuration root must be a YAML mapping")
    return Config.model_validate(payload)


def save_config(config: Config, root: Path | None = None) -> Path:
    path = config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path
