"""Safe filesystem helpers.

All reads treat input as untrusted: sizes are bounded and errors are converted
to diagnostics rather than exceptions. Writes are confined to a designated
output root.
"""

from __future__ import annotations

from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic, Severity, make_diagnostic
from pydeepmesh.errors import SecurityError


class ReadResult:
    """The outcome of a bounded, defensive file read."""

    __slots__ = ("diagnostic", "text")

    def __init__(self, text: str | None, diagnostic: Diagnostic | None) -> None:
        self.text = text
        self.diagnostic = diagnostic

    @property
    def ok(self) -> bool:
        return self.text is not None


def safe_read_text(
    path: Path,
    *,
    max_bytes: int,
    root: Path | None = None,
    code: str = "io.read",
) -> ReadResult:
    """Read a text file with a hard size cap.

    Symlinks are resolved and must stay within ``root`` when provided.
    """

    try:
        if root is not None:
            ensure_within(path, root)
        stat = path.stat()
        if stat.st_size > max_bytes:
            return ReadResult(
                None,
                make_diagnostic(
                    Severity.ERROR,
                    "io.too_large",
                    f"file is {stat.st_size} bytes, exceeds limit of {max_bytes}",
                    path=path,
                    root=root,
                    hint="raise --max-file-bytes if this is expected",
                ),
            )
        text = path.read_text(encoding="utf-8", errors="replace")
        return ReadResult(text, None)
    except SecurityError as exc:
        return ReadResult(
            None, make_diagnostic(Severity.ERROR, "io.path_escape", str(exc), path=path, root=root)
        )
    except (OSError, UnicodeError) as exc:
        return ReadResult(
            None,
            make_diagnostic(
                Severity.ERROR, code, f"could not read file: {exc}", path=path, root=root
            ),
        )


def ensure_within(path: Path, root: Path) -> Path:
    """Return the resolved path, raising if it escapes ``root``."""

    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise SecurityError(f"path '{path}' escapes root '{root}'")
    return resolved


def ensure_output_path(path: Path, output_root: Path) -> Path:
    """Validate that an output path stays within ``output_root``."""

    output_root = output_root.resolve()
    resolved = path.expanduser().absolute()
    parent = resolved.parent.resolve()
    if parent != output_root and output_root not in parent.parents:
        raise SecurityError(f"output path '{path}' escapes output root '{output_root}'")
    return resolved
