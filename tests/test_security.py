"""Path-safety, boundary, and untrusted-input handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from pydeepmesh.advisories.cache import Cache
from pydeepmesh.discovery.scanner import discover
from pydeepmesh.errors import SecurityError
from pydeepmesh.io import ensure_output_path, ensure_within, safe_read_text


def test_ensure_within_accepts_inside(tmp_path: Path) -> None:
    inside = tmp_path / "a" / "b.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("ok")
    assert ensure_within(inside, tmp_path) == inside.resolve()


def test_ensure_within_rejects_escape(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        ensure_within(tmp_path / ".." / "evil", tmp_path)


def test_ensure_output_path_accepts_within(tmp_path: Path) -> None:
    target = tmp_path / "out" / "x.json"
    assert ensure_output_path(target, tmp_path) == target.resolve()


def test_ensure_output_path_rejects_escape(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        ensure_output_path(tmp_path / ".." / "x.json", tmp_path)


def test_safe_read_text_too_large(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("x" * 100)
    result = safe_read_text(big, max_bytes=10, root=tmp_path)
    assert not result.ok
    assert result.diagnostic is not None
    assert result.diagnostic.code == "io.too_large"


def test_safe_read_text_missing_file(tmp_path: Path) -> None:
    result = safe_read_text(tmp_path / "missing.txt", max_bytes=10, root=tmp_path)
    assert not result.ok
    assert result.diagnostic is not None


def test_cache_keys_cannot_escape_directory(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl_seconds=-1)
    cache.set("../../evil", "../../../etc/passwd", {"x": 1})
    written = list(tmp_path.rglob("*.json"))
    assert written
    for path in written:
        assert path.resolve().is_relative_to(tmp_path.resolve())
    assert cache.get("../../evil", "../../../etc/passwd") == {"x": 1}


def test_discovery_skips_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "package.json").write_text('{"name": "evil", "version": "1.0.0"}')

    root = tmp_path / "root"
    root.mkdir()
    (root / "package.json").write_text('{"name": "good", "version": "1.0.0"}')
    (root / "linked").symlink_to(outside, target_is_directory=True)

    result = discover(root)
    names = {f.rel_path for f in result.files}
    assert "package.json" in names
    assert not any("linked" in name for name in names)
    assert any(d.code == "discovery.symlink_escape" for d in result.diagnostics)


def test_discovery_missing_root(tmp_path: Path) -> None:
    result = discover(tmp_path / "nope")
    assert not result.files
    assert any(d.code == "discovery.missing_root" for d in result.diagnostics)
