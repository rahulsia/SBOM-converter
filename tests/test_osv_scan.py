# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from sbom_converter import osv_scan


def _doc():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "jinja", "name": "jinja2", "version": "2.4.1", "purl": "pkg:pypi/jinja2@2.4.1"},
            {"type": "library", "bom-ref": "local", "name": "local-only", "version": "1.0"},
        ],
        "vulnerabilities": [
            {
                "id": "GHSA-test-test-test",
                "affects": [{"ref": "jinja"}],
                "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "feature disabled"},
            }
        ],
    }


def test_osv_scan_correlates_without_claiming_exploitability(monkeypatch):
    monkeypatch.setattr(osv_scan, "query_osv", lambda purl, timeout=15: [
        {"id": "GHSA-test-test-test", "aliases": ["CVE-2099-0001"], "summary": "sample", "modified": "2099-01-01T00:00:00Z"}
    ])
    report = osv_scan.scan_osv(_doc())
    assert report["componentsExamined"] == 2
    assert report["componentsQueried"] == 1
    assert report["vulnerabilityMatches"] == 1
    finding = report["findings"][0]
    assert finding["exploitability"] == "not_determined_by_osv"
    assert finding["vexStatus"] == "not_affected"
    assert finding["vex"]["justification"] == "code_not_reachable"
    assert report["componentsSkipped"][0]["reason"] == "missing_purl"


def test_osv_scan_skips_unversioned_purl(monkeypatch):
    doc = _doc()
    doc["components"] = [{"type": "library", "name": "x", "version": "1.0", "purl": "pkg:pypi/x"}]
    monkeypatch.setattr(osv_scan, "query_osv", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not query")))
    report = osv_scan.scan_osv(doc)
    assert report["componentsQueried"] == 0
    assert report["componentsSkipped"][0]["reason"] == "unversioned_purl"
