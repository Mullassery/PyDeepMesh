"""PyDeepMesh configuration: defaults, optional file, environment overlay."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from pydeepmesh._compat import tomllib
from pydeepmesh.errors import ConfigError

_ENV_PREFIX = "PYDEEPMESH_"


@dataclass
class Config:
    """Runtime configuration.

    Defaults are safe: offline, bounded, no writes outside the output root.
    """

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    max_file_bytes: int = 5 * 1024 * 1024
    max_files: int = 20000
    max_depth: int = 64
    online: bool = False
    advisory_dir: Path | None = None
    cache_dir: Path = field(default_factory=lambda: Path(".pydeepmesh-cache"))
    output_root: Path = field(default_factory=lambda: Path("."))
    network_timeout: float = 15.0
    network_retries: int = 2
    network_max_bytes: int = 32 * 1024 * 1024
    max_paths: int = 8
    cache_ttl_seconds: int = 24 * 60 * 60
    fail_on: str = "never"

    @classmethod
    def load(cls, path: Path | None = None, *, env: dict[str, str] | None = None) -> Config:
        config = cls()
        if path is not None:
            config = config.merged_with_file(path)
        config = config.merged_with_env(env if env is not None else dict(os.environ))
        return config

    def merged_with_file(self, path: Path) -> Config:
        if not path.exists():
            raise ConfigError(f"config file not found: {path}")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"could not read config {path}: {exc}") from exc
        section = data.get("tool", {}).get("pydeepmesh", data.get("pydeepmesh", {}))
        if not isinstance(section, dict):
            return self
        return self._apply_mapping(section)

    def merged_with_env(self, env: dict[str, str]) -> Config:
        config = self
        if value := env.get(f"{_ENV_PREFIX}ONLINE"):
            config = replace(config, online=_as_bool(value))
        if value := env.get(f"{_ENV_PREFIX}CACHE_DIR"):
            config = replace(config, cache_dir=Path(value))
        if value := env.get(f"{_ENV_PREFIX}ADVISORY_DIR"):
            config = replace(config, advisory_dir=Path(value))
        if value := env.get(f"{_ENV_PREFIX}MAX_FILE_BYTES"):
            config = replace(config, max_file_bytes=_as_int(value, "PYDEEPMESH_MAX_FILE_BYTES"))
        if value := env.get(f"{_ENV_PREFIX}NETWORK_TIMEOUT"):
            config = replace(config, network_timeout=_as_float(value, "PYDEEPMESH_NETWORK_TIMEOUT"))
        return config

    def _apply_mapping(self, section: dict[str, object]) -> Config:
        config = replace(self)
        include = section.get("include")
        if isinstance(include, list):
            config.include = tuple(str(v) for v in include)
        exclude = section.get("exclude")
        if isinstance(exclude, list):
            config.exclude = tuple(str(v) for v in exclude)
        if "max_file_bytes" in section:
            config.max_file_bytes = _coerce_int(section["max_file_bytes"], "max_file_bytes")
        if "max_files" in section:
            config.max_files = _coerce_int(section["max_files"], "max_files")
        if "online" in section:
            config.online = bool(section["online"])
        if "cache_dir" in section:
            config.cache_dir = Path(str(section["cache_dir"]))
        if "advisory_dir" in section:
            config.advisory_dir = Path(str(section["advisory_dir"]))
        if "fail_on" in section:
            config.fail_on = str(section["fail_on"])
        return config


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str, name: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _as_float(value: str, name: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc


def _coerce_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    return value
