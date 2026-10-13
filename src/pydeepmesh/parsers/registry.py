"""Registry of available parsers."""

from __future__ import annotations

from pathlib import Path

from pydeepmesh.parsers.base import Parser
from pydeepmesh.parsers.container.compose import ComposeParser
from pydeepmesh.parsers.container.dockerfile import DockerfileParser
from pydeepmesh.parsers.node.package_json import PackageJsonParser
from pydeepmesh.parsers.node.package_lock import PackageLockParser
from pydeepmesh.parsers.node.pnpm_lock import PnpmLockParser
from pydeepmesh.parsers.node.yarn_lock import YarnLockParser
from pydeepmesh.parsers.python.poetry_lock import PoetryLockParser
from pydeepmesh.parsers.python.pyproject import PyprojectParser
from pydeepmesh.parsers.python.requirements import RequirementsParser
from pydeepmesh.parsers.python.uv_lock import UvLockParser
from pydeepmesh.parsers.rust.cargo_lock import CargoLockParser
from pydeepmesh.parsers.rust.cargo_manifest import CargoManifestParser


def default_parsers() -> list[Parser]:
    """Return the ordered list of built-in parsers.

    Order matters when several parsers can match; specific files are listed
    before suffix-based matches.
    """

    return [
        PyprojectParser(),
        PoetryLockParser(),
        UvLockParser(),
        RequirementsParser(),
        CargoManifestParser(),
        CargoLockParser(),
        PackageJsonParser(),
        PackageLockParser(),
        PnpmLockParser(),
        YarnLockParser(),
        DockerfileParser(),
        ComposeParser(),
    ]


def parsers_for(path: Path, parsers: list[Parser] | None = None) -> list[Parser]:
    candidates = parsers if parsers is not None else default_parsers()
    return [parser for parser in candidates if parser.matches(path)]
