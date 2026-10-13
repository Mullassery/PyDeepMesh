"""Content-addressed on-disk cache for advisory data."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from pydeepmesh.io import ensure_output_path


class Cache:
    """A small TTL cache backed by JSON files.

    Keys are hashed so untrusted identifiers cannot influence the filesystem
    path. All writes are confined to the cache directory.
    """

    def __init__(self, directory: Path, *, ttl_seconds: int = 24 * 60 * 60) -> None:
        self.directory = directory
        self.ttl_seconds = ttl_seconds
        self.hits = 0
        self.misses = 0

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        safe_namespace = "".join(c for c in namespace if c.isalnum() or c in "-_") or "default"
        target = self.directory / safe_namespace / f"{digest}.json"
        ensure_output_path(target, self.directory)
        return target

    def get(self, namespace: str, key: str) -> Any | None:
        path = self._path(namespace, key)
        if not path.exists():
            self.misses += 1
            return None
        if self.ttl_seconds >= 0:
            age = time.time() - path.stat().st_mtime
            if age > self.ttl_seconds:
                self.misses += 1
                return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.misses += 1
            return None
        self.hits += 1
        return payload

    def set(self, namespace: str, key: str, value: Any) -> None:
        path = self._path(namespace, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            return

    def clear(self) -> int:
        removed = 0
        if not self.directory.exists():
            return removed
        for path in sorted(self.directory.rglob("*.json")):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed
