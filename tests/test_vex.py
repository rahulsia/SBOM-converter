# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
import json

import pytest

from sbom_converter.cli import main
from sbom_converter.vex import (
    OPENVEX_CONTEXT,
    VexError,
    build_vex,
    extract_products,
    validate_vex,
    validate_vex_input,
)


def cdx():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "libfoo", "name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"},
            {"type": "library", "bom-ref": "libbar", "name": "libbar", "version": "2.0.0"},
        ],
    }


def spdx2():
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "demo",
        "documentNamespace": "https://example.test/demo",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Person: Test"]},
        "packages": [{"name": "libfoo", "SPDXID": "SPDXRef-libfoo", "versionInfo": "1.2.3"}],
    }


def not_affected():
    return [{"id": "CVE-2024-1", "status": "not_affected", "justification": "vulnerable_code_not_present"}]


def affected():
    return [{"id": "CVE-2024-2", "status": "affected", "action_statement": "Upgrade to 1.2.4"}]


def test_extract_products_cdx():
    entries = extract_products(cdx())
    assert {"name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"} in entries
    assert {"name": "libbar", "version": "2.0.0", "purl": None} in entries


def test_extract_products_spdx2():
    entries = extract_products(spdx2())
    assert entries == [{"name": "libfoo", "version": "1.2.3", "purl": None}]


def test_build_vex_valid_document():
    doc = build_vex(cdx(), not_affected())
    assert doc["@context"] == OPENVEX_CONTEXT
    assert doc["version"] == 1
    assert len(doc["statements"]) == 1
    assert validate_vex(doc) is True


def test_build_vex_applies_to_all_products_when_unspecified():
    doc = build_vex(cdx(), not_affected())
    ids = {p["@id"] for p in doc["statements"][0]["products"]}
    assert ids == {"pkg:pypi/libfoo@1.2.3", "libbar@2.0.0"}


def test_build_vex_targets_specific_product():
    vulns = [{"id": "CVE-2024-3", "status": "affected", "action_statement": "patch", "products": ["libfoo"]}]
    doc = build_vex(cdx(), vulns)
    ids = {p["@id"] for p in doc["statements"][0]["products"]}
    assert ids == {"pkg:pypi/libfoo@1.2.3"}


def test_build_vex_unknown_product_raises():
    vulns = [{"id": "CVE-2024-4", "status": "affected", "action_statement": "patch", "products": ["ghost"]}]
    with pytest.raises(VexError, match="unknown product"):
        build_vex(cdx(), vulns)


def test_build_vex_no_components_raises():
    with pytest.raises(VexError, match="No identifiable components"):
        build_vex({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}, not_affected())


def test_build_vex_custom_author():
    doc = build_vex(cdx(), not_affected(), author="Security Team <sec@example.test>")
    assert doc["author"] == "Security Team <sec@example.test>"


def test_validate_vex_input_requires_list():
    with pytest.raises(VexError, match="JSON array"):
        validate_vex_input({"id": "CVE-2024-1", "status": "affected"})


def test_validate_vex_input_requires_id():
    with pytest.raises(VexError, match="required 'id'"):
        validate_vex_input([{"status": "affected", "action_statement": "x"}])


def test_validate_vex_input_rejects_bad_status():
    with pytest.raises(VexError, match="invalid status"):
        validate_vex_input([{"id": "CVE-2024-1", "status": "maybe"}])


def test_validate_vex_input_not_affected_requires_justification():
    with pytest.raises(VexError, match="requires 'justification'"):
        validate_vex_input([{"id": "CVE-2024-1", "status": "not_affected"}])


def test_validate_vex_input_rejects_bad_justification():
    with pytest.raises(VexError, match="invalid justification"):
        validate_vex_input([{"id": "CVE-2024-1", "status": "not_affected", "justification": "nope"}])


def test_validate_vex_input_affected_requires_action_statement():
    with pytest.raises(VexError, match="requires 'action_statement'"):
        validate_vex_input([{"id": "CVE-2024-1", "status": "affected"}])


def test_validate_vex_input_accepts_impact_statement_for_not_affected():
    data = validate_vex_input([{"id": "CVE-2024-1", "status": "not_affected", "impact_statement": "No impact."}])
    assert data[0]["status"] == "not_affected"


def test_validate_vex_rejects_wrong_context():
    doc = build_vex(cdx(), not_affected())
    doc["@context"] = "https://example.test/wrong"
    with pytest.raises(VexError, match="@context"):
        validate_vex(doc)


def test_validate_vex_rejects_missing_statements():
    doc = build_vex(cdx(), not_affected())
    doc["statements"] = []
    with pytest.raises(VexError, match="non-empty list"):
        validate_vex(doc)


def test_validate_vex_rejects_non_dict():
    with pytest.raises(VexError, match="JSON object"):
        validate_vex([])


def test_cli_vex_generates_document_from_vex_input(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    vulns = tmp_path / "vulns.json"
    vulns.write_text(json.dumps(not_affected()))
    out = tmp_path / "vex.json"
    assert main([str(sbom), "--vex", "--vex-input", str(vulns), "--vex-output", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["@context"] == OPENVEX_CONTEXT
    assert len(doc["statements"]) == 1


def test_cli_vex_requires_vex_output(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    vulns = tmp_path / "vulns.json"
    vulns.write_text(json.dumps(not_affected()))
    with pytest.raises(SystemExit):
        main([str(sbom), "--vex", "--vex-input", str(vulns)])


def test_cli_vex_input_requires_vex_flag(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    vulns = tmp_path / "vulns.json"
    vulns.write_text(json.dumps(not_affected()))
    out = tmp_path / "vex.json"
    with pytest.raises(SystemExit):
        main([str(sbom), "--vex-input", str(vulns), "--vex-output", str(out)])


def test_cli_vex_invalid_input_returns_error_code(tmp_path, capsys):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    vulns = tmp_path / "vulns.json"
    vulns.write_text(json.dumps([{"id": "CVE-2024-1", "status": "bogus"}]))
    out = tmp_path / "vex.json"
    assert main([str(sbom), "--vex", "--vex-input", str(vulns), "--vex-output", str(out)]) == 3
    assert "ERROR" in capsys.readouterr().err


def test_cli_vex_combined_with_conversion(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    vulns = tmp_path / "vulns.json"
    vulns.write_text(json.dumps(affected()))
    vex_out = tmp_path / "vex.json"
    converted_out = tmp_path / "converted.json"
    rc = main(
        [
            str(sbom),
            "--to",
            "cdx-1.7",
            "-o",
            str(converted_out),
            "--vex",
            "--vex-input",
            str(vulns),
            "--vex-output",
            str(vex_out),
        ]
    )
    assert rc == 0
    assert converted_out.exists()
    assert vex_out.exists()


def test_cli_requires_an_action(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    with pytest.raises(SystemExit):
        main([str(sbom)])


def test_cli_vex_auto_lookup_uses_osv(tmp_path, monkeypatch):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    out = tmp_path / "vex.json"

    def fake_lookup(entries, timeout=15, on_query=None):
        assert {e["name"] for e in entries} == {"libfoo", "libbar"}
        return (
            [
                {
                    "id": "OSV-2024-1",
                    "status": "under_investigation",
                    "status_notes": "Detected via OSV.dev against pkg:pypi/libfoo@1.2.3.",
                    "products": ["libfoo"],
                }
            ],
            ["libbar"],
        )

    monkeypatch.setattr("sbom_converter.cli.lookup_vulnerabilities", fake_lookup)
    rc = main([str(sbom), "--vex", "--vex-output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["statements"][0]["vulnerability"]["name"] == "OSV-2024-1"


def test_cli_vex_auto_lookup_no_vulns_found(tmp_path, monkeypatch):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(cdx()))
    out = tmp_path / "vex.json"

    monkeypatch.setattr("sbom_converter.cli.lookup_vulnerabilities", lambda entries, timeout=15, on_query=None: ([], []))
    rc = main([str(sbom), "--vex", "--vex-output", str(out)])
    assert rc == 0
    assert not out.exists()
