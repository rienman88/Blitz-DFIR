from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from blitz_dfir.exceptions import ValidationError


class ToolSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool = True
    executable: str = Field(min_length=1)
    version: str | None = None
    expected_sha256: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=7200)
    allowed_plugins: tuple[str, ...] = ()
    allowed_rules: tuple[str, ...] = ()
    symbols_dir: str | None = None


class ToolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: dict[str, ToolSettings]

    def require(self, tool_name: str) -> ToolSettings:
        try:
            settings = self.tools[tool_name]
        except KeyError as exc:
            raise ValidationError(f"tool is missing from config: {tool_name}") from exc
        if not settings.allowed:
            raise ValidationError(f"tool is disabled in config: {tool_name}")
        return settings


def load_tool_config(path: Path | str = Path("config/tools.yaml")) -> ToolConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"tool config not found: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ValidationError(f"invalid tool config YAML: {config_path}") from exc
    try:
        return ToolConfig.model_validate(raw)
    except PydanticValidationError as exc:
        raise ValidationError(str(exc)) from exc
