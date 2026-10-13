"""Structured diagnostics for untrusted-input problems.

Parsers and providers never raise for malformed, unsupported, or incomplete
input; they emit :class:`Diagnostic` records so callers can decide how to react
and so reports can surface them transparently.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Severity(enum.IntEnum):
    """Diagnostic severity, ordered from least to most serious."""

    INFO = 0
    WARNING = 1
    ERROR = 2

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Diagnostic:
    """A single structured diagnostic message."""

    severity: Severity
    code: str
    message: str
    file: str | None = None
    line: int | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "severity": self.severity.label,
            "code": self.code,
            "message": self.message,
        }
        if self.file is not None:
            data["file"] = self.file
        if self.line is not None:
            data["line"] = self.line
        if self.hint is not None:
            data["hint"] = self.hint
        return data

    def render(self) -> str:
        location = ""
        if self.file is not None:
            location = f" {self.file}"
            if self.line is not None:
                location += f":{self.line}"
        rendered = f"{self.severity.label}: [{self.code}]{location}: {self.message}"
        if self.hint:
            rendered += f" ({self.hint})"
        return rendered


def make_diagnostic(
    severity: Severity,
    code: str,
    message: str,
    *,
    path: Path | None = None,
    root: Path | None = None,
    line: int | None = None,
    hint: str | None = None,
) -> Diagnostic:
    """Build a diagnostic, relativizing the file path to ``root`` when possible."""

    display: str | None = None
    if path is not None:
        display = str(path)
        if root is not None:
            try:
                display = str(path.resolve().relative_to(root.resolve()))
            except (ValueError, OSError):
                display = str(path)
    return Diagnostic(
        severity=severity,
        code=code,
        message=message,
        file=display,
        line=line,
        hint=hint,
    )


@dataclass
class DiagnosticCollector:
    """Accumulates diagnostics and provides ordering/aggregation helpers."""

    items: list[Diagnostic] = field(default_factory=list)

    def add(self, diagnostic: Diagnostic) -> None:
        self.items.append(diagnostic)

    def info(self, code: str, message: str, **kwargs: object) -> None:
        self._emit(Severity.INFO, code, message, kwargs)

    def warning(self, code: str, message: str, **kwargs: object) -> None:
        self._emit(Severity.WARNING, code, message, kwargs)

    def error(self, code: str, message: str, **kwargs: object) -> None:
        self._emit(Severity.ERROR, code, message, kwargs)

    def extend(self, diagnostics: list[Diagnostic] | DiagnosticCollector) -> None:
        if isinstance(diagnostics, DiagnosticCollector):
            self.items.extend(diagnostics.items)
        else:
            self.items.extend(diagnostics)

    def _emit(self, severity: Severity, code: str, message: str, kwargs: dict[str, object]) -> None:
        self.add(make_diagnostic(severity, code, message, **kwargs))  # type: ignore[arg-type]

    @property
    def has_errors(self) -> bool:
        return any(d.severity is Severity.ERROR for d in self.items)

    def count(self, severity: Severity) -> int:
        return sum(1 for d in self.items if d.severity is severity)

    def sorted(self) -> list[Diagnostic]:
        return sorted(
            self.items,
            key=lambda d: (
                d.file or "",
                d.line or 0,
                int(d.severity),
                d.code,
                d.message,
            ),
        )

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)
