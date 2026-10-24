"""CycloneDX 1.5 SBOM generation and schema validity."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from helpers import scan_fixture
from pydeepmesh.sbom.cyclonedx import SPEC_VERSION, build_cyclonedx, render_cyclonedx

SCHEMAS = Path(__file__).parent / "schemas"


def test_cyclonedx_matches_schema() -> None:
    scan = scan_fixture("python_project")
    document = build_cyclonedx(scan)
    schema = json.loads((SCHEMAS / "cyclonedx-1.5.schema.json").read_text())
    Draft7Validator(schema).validate(document)


def test_cyclonedx_is_deterministic_without_timestamp() -> None:
    first = render_cyclonedx(build_cyclonedx(scan_fixture("node_project")))
    second = render_cyclonedx(build_cyclonedx(scan_fixture("node_project")))
    assert first == second
    assert "timestamp" not in json.loads(first)["metadata"]


def test_cyclonedx_serial_number_stable() -> None:
    first = build_cyclonedx(scan_fixture("rust_project"))["serialNumber"]
    second = build_cyclonedx(scan_fixture("rust_project"))["serialNumber"]
    assert first == second
    assert first.startswith("urn:uuid:")


def test_cyclonedx_components_have_purls() -> None:
    document = build_cyclonedx(scan_fixture("node_project"))
    purls = {component["purl"] for component in document["components"] if "purl" in component}
    assert any(purl.startswith("pkg:npm/") for purl in purls)


def test_cyclonedx_dependencies_reference_known_components() -> None:
    document = build_cyclonedx(scan_fixture("node_project"))
    refs = {component["bom-ref"] for component in document["components"]}
    for dependency in document["dependencies"]:
        assert dependency["ref"] in refs
        for target in dependency["dependsOn"]:
            assert target in refs


def test_cyclonedx_spec_version() -> None:
    assert build_cyclonedx(scan_fixture("node_project"))["specVersion"] == SPEC_VERSION


def test_spdx_matches_expected_shape() -> None:
    from pydeepmesh.sbom.spdx import SPDX_VERSION, build_spdx

    scan = scan_fixture("python_project")
    document = build_spdx(scan, timestamp="2026-10-24T00:00:00Z")
    assert document["spdxVersion"] == SPDX_VERSION
    assert document["dataLicense"] == "CC0-1.0"
    assert document["SPDXID"] == "SPDXRef-DOCUMENT"
    assert document["creationInfo"]["created"] == "2026-10-24T00:00:00Z"
    assert any(p["SPDXID"] != "SPDXRef-DOCUMENT" for p in document["packages"])
    described = [
        r
        for r in document["relationships"]
        if r["relationshipType"] == "DESCRIBES"
    ]
    assert len(described) == 1
    assert described[0]["relatedSpdxElement"] in {
        p["SPDXID"] for p in document["packages"]
    }


def test_spdx_is_deterministic_and_relationships_resolve() -> None:
    from pydeepmesh.sbom.spdx import build_spdx, render_spdx

    scan = scan_fixture("node_project")
    first = render_spdx(build_spdx(scan))
    second = render_spdx(build_spdx(scan))
    assert first == second
    document = build_spdx(scan)
    ids = {p["SPDXID"] for p in document["packages"]}
    for relationship in document["relationships"]:
        assert relationship["spdxElementId"] in ids or relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
        assert relationship["relatedSpdxElement"] in ids
