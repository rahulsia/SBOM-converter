# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

import json
import urllib.error

import pytest

from sbom_converter.nvd import (
    NvdError,
    NvdFinding,
    extract_cpe_entries,
    nvd_report,
    query_nvd_cpe,
    scan_nvd,
)


def test_extract_cpes_from_spdx23():
    doc = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "foo",
                "versionInfo": "1.2.3",
                "externalRefs": [
                    {
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:vendor:foo:1.2.3:*:*:*:*:*:*:*",
                    }
                ],
            }
        ],
    }
    entries = extract_cpe_entries(doc)
    assert entries == [{
        "name": "foo",
        "version": "1.2.3",
        "cpe": "cpe:2.3:a:vendor:foo:1.2.3:*:*:*:*:*:*:*",
    }]


def test_query_nvd_cpe_parses_cve_and_cvss(monkeypatch):
    calls = []

    def fake_post(url, headers, timeout):
        calls.append((url, headers, timeout))
        return {
            "totalResults": 1,
            "resultsPerPage": 2000,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-12345",
                    "published": "2025-01-01T00:00:00.000",
                    "lastModified": "2025-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                            }
                        }]
                    },
                }
            }],
        }

    monkeypatch.setattr("sbom_converter.nvd._post_json", fake_post)
    result = query_nvd_cpe(
        "cpe:2.3:a:vendor:foo:1.2.3:*:*:*:*:*:*:*",
        min_delay=0,
    )
    assert calls[0][0].startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert result[0]["id"] == "CVE-2025-12345"
    assert result[0]["cvssBaseScore"] == 8.8
    assert result[0]["cvssSeverity"] == "HIGH"


def test_query_nvd_cpe_follows_pagination(monkeypatch):
    calls = []

    def fake_post(url, headers, timeout):
        calls.append(url)
        start = "startIndex=0" in url
        return {
            "totalResults": 2,
            "resultsPerPage": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-1" if start else "CVE-2",
                    "descriptions": [],
                }
            }],
        }

    monkeypatch.setattr("sbom_converter.nvd._post_json", fake_post)
    result = query_nvd_cpe("cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", min_delay=0)
    assert [x["id"] for x in result] == ["CVE-1", "CVE-2"]
    assert "startIndex=1" in calls[1]


def test_scan_nvd_deduplicates_cpes(monkeypatch):
    calls = []

    def fake_query(cpe, timeout=20, api_key=None, min_delay=None):
        calls.append(cpe)
        return [{"id": "CVE-1", "published": None, "lastModified": None}]
    
    monkeypatch.setattr("sbom_converter.nvd.query_nvd_cpe", fake_query)
    entries = [
        {"name": "foo", "version": "1", "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
        {"name": "foo-copy", "version": "1", "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
    ]
    findings, skipped = scan_nvd(entries, min_delay=0)
    assert calls == ["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]
    assert findings[0].vulnerability_id == "CVE-1"
    assert skipped == []


def test_nvd_finding_never_asserts_exploitability():
    finding = NvdFinding(
        "foo", "1.0", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", "CVE-1"
    )
    assert finding.as_dict()["exploitability"] == "not_determined_by_nvd"


def test_nvd_report_is_machine_readable():
    report = nvd_report(
        [{"name": "foo", "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"}],
        [NvdFinding("foo", "1", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", "CVE-1")],
        [],
        False,
    )
    json.dumps(report)
    assert report["source"] == "NVD/NIST"
    assert report["endpoint"] == "https://services.nvd.nist.gov/rest/json/cves/2.0"


def test_nvd_http_failure_is_explicit(monkeypatch):
    def fake_urlopen(req, timeout=20):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr("sbom_converter.nvd.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(NvdError, match="NVD lookup failed"):
        from sbom_converter.nvd import _post_json
        _post_json("https://services.nvd.nist.gov/rest/json/cves/2.0", {}, 20)
