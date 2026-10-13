"""Source provenance for graph elements."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class SourceLocation:
    """Where a fact was observed.

    ``file`` is repository-relative and ``line`` is 1-based when known.
    """

    file: str
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"file": self.file}
        if self.line is not None:
            data["line"] = self.line
        return data

    def render(self) -> str:
        if self.line is None:
            return self.file
        return f"{self.file}:{self.line}"
