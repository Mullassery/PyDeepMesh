"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from pydeepmesh.config import Config


@pytest.fixture
def config() -> Config:
    return Config()
