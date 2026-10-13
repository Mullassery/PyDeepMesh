"""Configuration loading from files and environment."""

from __future__ import annotations

from pathlib import Path

import pytest

from pydeepmesh.config import Config
from pydeepmesh.errors import ConfigError


def test_defaults_are_offline_and_bounded() -> None:
    config = Config()
    assert config.online is False
    assert config.max_file_bytes > 0
    assert config.fail_on == "never"


def test_env_overrides() -> None:
    config = Config().merged_with_env(
        {
            "PYDEEPMESH_ONLINE": "1",
            "PYDEEPMESH_CACHE_DIR": "/tmp/cache",
            "PYDEEPMESH_MAX_FILE_BYTES": "1024",
            "PYDEEPMESH_NETWORK_TIMEOUT": "2.5",
        }
    )
    assert config.online is True
    assert config.cache_dir == Path("/tmp/cache")
    assert config.max_file_bytes == 1024
    assert config.network_timeout == 2.5


def test_invalid_env_int_raises() -> None:
    with pytest.raises(ConfigError):
        Config().merged_with_env({"PYDEEPMESH_MAX_FILE_BYTES": "not-an-int"})


def test_file_overrides(tmp_path: Path) -> None:
    config_file = tmp_path / "pydeepmesh.toml"
    config_file.write_text(
        "[tool.pydeepmesh]\n"
        'include = ["*.txt"]\n'
        'exclude = ["vendor"]\n'
        "max_files = 10\n"
        "online = true\n"
        'fail_on = "high"\n'
    )
    config = Config.load(config_file)
    assert config.include == ("*.txt",)
    assert config.exclude == ("vendor",)
    assert config.max_files == 10
    assert config.online is True
    assert config.fail_on == "high"


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.load(tmp_path / "nope.toml")


def test_invalid_type_in_file_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "pydeepmesh.toml"
    config_file.write_text('[tool.pydeepmesh]\nmax_files = "many"\n')
    with pytest.raises(ConfigError):
        Config.load(config_file)
