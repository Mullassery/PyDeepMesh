"""Python (PyPI) parsers."""

from __future__ import annotations

from pydeepmesh.parsers.python.poetry_lock import PoetryLockParser
from pydeepmesh.parsers.python.pyproject import PyprojectParser
from pydeepmesh.parsers.python.requirements import RequirementsParser
from pydeepmesh.parsers.python.uv_lock import UvLockParser

__all__ = ["PoetryLockParser", "PyprojectParser", "RequirementsParser", "UvLockParser"]
