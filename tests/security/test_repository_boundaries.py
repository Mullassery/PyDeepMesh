"""Repository-boundary enforcement tests.

This file is permitted to mention sibling repository names because it verifies
that the boundary checker detects them.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_boundaries.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_boundaries", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_boundaries"] = module
    spec.loader.exec_module(module)
    return module


def test_checker_runs_clean_on_this_repo() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_checker_detects_sibling_reference(tmp_path: Path, monkeypatch) -> None:
    checker = _load_checker()
    (tmp_path / "code.py").write_text("import PyDependencyCheck  # forbidden\n")
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    violations = checker.check_sibling_references()
    assert any(v.rule == "sibling-reference" for v in violations)


def test_checker_detects_nested_repo(tmp_path: Path, monkeypatch) -> None:
    checker = _load_checker()
    nested = tmp_path / "inner" / ".git"
    nested.mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    violations = checker.check_submodules_and_nested_repos()
    assert any(v.rule == "nested-repo" for v in violations)
    assert not any(v.rule == "nested-repo" and "inner" not in v.path for v in violations)


def test_checker_detects_path_dependency(tmp_path: Path, monkeypatch) -> None:
    checker = _load_checker()
    (tmp_path / "pyproject.toml").write_text('dep = { path = "../sibling" }\n')
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    violations = checker.check_path_dependencies()
    assert violations
