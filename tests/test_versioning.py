"""Tests for ecosystem-aware version comparison and range matching."""

from __future__ import annotations

import pytest

from pydeepmesh.advisories.cvss import base_score
from pydeepmesh.advisories.versioning import (
    SemVer,
    compare_versions,
    earliest_fixed_version,
    version_in_affected,
    version_in_range,
)
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.vulnerability import AffectedPackage, VersionRange


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.0.1", -1),
        ("1.10.0", "1.9.0", 1),
        ("2.0.0", "2.0.0", 0),
        ("1.0.0a1", "1.0.0", -1),
        ("1.0.0", "1.0.0.dev1", 1),
    ],
)
def test_pep440_compare(left: str, right: str, expected: int) -> None:
    assert compare_versions(Ecosystem.PYPI, left, right) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.3", "1.2.4", -1),
        ("1.10.0", "1.9.9", 1),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),
        ("1.2", "1.2.0", 0),
    ],
)
def test_semver_compare(left: str, right: str, expected: int) -> None:
    assert compare_versions(Ecosystem.NPM, left, right) == expected


def test_semver_parse_partial() -> None:
    parsed = SemVer.parse("1.2")
    assert parsed is not None
    assert (parsed.major, parsed.minor, parsed.patch) == (1, 2, 0)


def test_version_in_range_introduced_fixed() -> None:
    events = (("introduced", "0"), ("fixed", "2.32.0"))
    assert version_in_range(Ecosystem.PYPI, "2.31.0", "ECOSYSTEM", events) is True
    assert version_in_range(Ecosystem.PYPI, "2.32.0", "ECOSYSTEM", events) is False
    assert version_in_range(Ecosystem.PYPI, "1.0.0", "ECOSYSTEM", events) is True


def test_version_in_range_limit() -> None:
    events = (("introduced", "0"), ("limit", "2.0.0"))
    assert version_in_range(Ecosystem.NPM, "1.9.9", "SEMVER", events) is True
    assert version_in_range(Ecosystem.NPM, "2.0.0", "SEMVER", events) is False


def test_version_in_range_last_affected() -> None:
    events = (("introduced", "1.0.0"), ("last_affected", "1.5.0"))
    assert version_in_range(Ecosystem.NPM, "1.5.0", "SEMVER", events) is True
    assert version_in_range(Ecosystem.NPM, "1.5.1", "SEMVER", events) is False


def test_git_range_is_unevaluable() -> None:
    assert version_in_range(Ecosystem.CRATES, "1.0.0", "GIT", (("introduced", "0"),)) is None


def test_explicit_versions() -> None:
    affected = AffectedPackage(
        name="pkg",
        ecosystem_raw="PyPI",
        ecosystem=Ecosystem.PYPI,
        versions=("1.0.0", "1.0.1"),
    )
    assert version_in_affected(Ecosystem.PYPI, "1.0.0", affected) is True
    assert version_in_affected(Ecosystem.PYPI, "1.0.2", affected) is False


def test_earliest_fixed_version() -> None:
    affected = AffectedPackage(
        name="pkg",
        ecosystem_raw="PyPI",
        ecosystem=Ecosystem.PYPI,
        ranges=(
            VersionRange(
                "ECOSYSTEM", (("introduced", "0"), ("fixed", "2.0.0"), ("fixed", "1.5.0"))
            ),
        ),
    )
    assert earliest_fixed_version(Ecosystem.PYPI, "1.2.0", affected) == "1.5.0"


def test_cvss_base_score() -> None:
    score = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert base_score("not-a-vector") is None
