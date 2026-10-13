"""Typed exceptions used across PyDeepMesh.

PyDeepMesh reserves exceptions for programmer errors and unrecoverable conditions.
Routine problems with untrusted input are reported as diagnostics, not raised.
"""

from __future__ import annotations


class PyDeepMeshError(Exception):
    """Base class for all PyDeepMesh errors."""


class UsageError(PyDeepMeshError):
    """Invalid command-line usage. Maps to exit code 2."""


class ConfigError(PyDeepMeshError):
    """Invalid or unreadable configuration. Maps to exit code 2."""


class InputError(PyDeepMeshError):
    """A scanned input could not be analyzed. Maps to exit code 3."""


class SecurityError(PyDeepMeshError):
    """A security constraint was violated (e.g. a path escaped the output root)."""


class AdvisoryUnavailableError(PyDeepMeshError):
    """Advisory data was required but could not be obtained. Maps to exit code 4."""


class AdvisoryProviderError(PyDeepMeshError):
    """An advisory provider returned a malformed or failed response."""
