# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from sbom_converter.core import Report
from sbom_converter.native_vex import analyze_cyclonedx_vex, augment_spdx3_with_cdx_vex


def sample_cdx():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "components": [{"type": "library", "bom-ref": "pkg-a", "name": "a", "version": "1.0", "purl": "pkg:pypi/a@1.0"}],
        "vulnerabilities": [{
            "id": "CVE-2026-1234",
            "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "Vulnerable path is not invoked."},
            "affects": [{"ref": "pkg-a"}],
        }],
    }


def sample_spdx3():
    return {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [
        {"type": "CreationInfo", "@id": "_:creationinfo", "specVersion": "3.0.1"},
        {"type": "software_Package", "spdxId": "urn:test:a", "creationInfo": "_:creationinfo", "name": "a", "externalIdentifier": [{"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl", "identifier": "pkg:pypi/a@1.0"}]},
        {"type": "SpdxDocument", "spdxId": "urn:test:doc", "creationInfo": "_:creationinfo", "profileConformance": ["core", "software"], "element": []},
        {"type": "software_Sbom", "spdxId": "urn:test:sbom", "creationInfo": "_:creationinfo", "profileConformance": ["core", "software"]},
    ]}


def test_analyze_vex_summary():
    result = analyze_cyclonedx_vex(sample_cdx())
    assert result["totalVulnerabilities"] == 1
    assert result["states"]["not_affected"] == 1
    assert result["justifications"]["code_not_reachable"] == 1
    assert result["affectedComponentRefs"] == ["pkg-a"]
    assert result["warnings"] == []


def test_not_affected_maps_to_spdx_security_profile():
    report = Report("cyclonedx-1.7", "spdx-3.0.1")
    out = augment_spdx3_with_cdx_vex(sample_cdx(), sample_spdx3(), report)
    rels = [x for x in out["@graph"] if x.get("type") == "security_VexNotAffectedVulnAssessmentRelationship"]
    assert len(rels) == 1
    assert rels[0]["relationshipType"] == "doesNotAffect"
    assert rels[0]["security_justificationType"] == "vulnerableCodeNotInExecutePath"
    doc = next(x for x in out["@graph"] if x.get("type") == "SpdxDocument")
    assert "security" in doc["profileConformance"]


def test_in_triage_is_not_guessed_into_affected_status():
    cdx = sample_cdx()
    cdx["vulnerabilities"][0]["analysis"] = {"state": "in_triage"}
    report = Report("cyclonedx-1.7", "spdx-3.0.1")
    out = augment_spdx3_with_cdx_vex(cdx, sample_spdx3(), report)
    assert not any("VexAffected" in x.get("type", "") for x in out["@graph"])
    assert any(w.code == "VEX_STATE_NOT_DIRECTLY_MAPPABLE" for w in report.warnings)


def test_not_affected_without_rationale_is_flagged():
    cdx = sample_cdx()
    cdx["vulnerabilities"][0]["analysis"] = {"state": "not_affected"}
    result = analyze_cyclonedx_vex(cdx)
    assert result["warnings"][0]["code"] == "NOT_AFFECTED_WITHOUT_RATIONALE"
