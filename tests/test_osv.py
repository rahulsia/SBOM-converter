# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

import json
import urllib.error

import pytest

from sbom_converter.osv import (
    OsvError,
    OsvFinding,
    lookup_vulnerabilities,
    osv_report,
    query_osv,
    query_osv_batch,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_query_osv_batch_uses_https_querybatch(monkeypatch):
    calls = []

    def fake_post(url, payload, timeout):
        calls.append((url, payload, timeout))
        return {
            "results": [
                {"vulns": [{"id": "OSV-2024-1", "modified": "2024-01-01T00:00:00Z"}]},
                {"vulns": []},
            ]
        }

    monkeypatch.setattr("sbom_converter.osv._post_json", fake_post)
    entries = [
        {"name": "a", "version": "1.0.0", "purl": "pkg:pypi/a@1.0.0"},
        {"name": "b", "version": "2.0.0", "purl": "pkg:pypi/b@2.0.0"},
    ]
    findings, skipped = query_osv_batch(entries)

    assert calls[0][0] == "https://api.osv.dev/v1/querybatch"
    assert len(calls) == 1
    assert len(calls[0][1]["queries"]) == 2
    assert calls[0][1]["queries"][0]["package"]["purl"] == "pkg:pypi/a@1.0.0"
    assert findings[0].vulnerability_id == "OSV-2024-1"
    assert skipped == []


def test_query_osv_batch_chunks_large_input(monkeypatch):
    calls = []

    def fake_post(url, payload, timeout):
        calls.append(payload)
        return {"results": [{"vulns": []} for _ in payload["queries"]]}

    monkeypatch.setattr("sbom_converter.osv._post_json", fake_post)
    entries = [
        {"name": f"pkg-{i}", "version": "1.0.0", "purl": f"pkg:generic/pkg-{i}@1.0.0"}
        for i in range(205)
    ]
    findings, skipped = query_osv_batch(entries, batch_size=100)

    assert [len(x["queries"]) for x in calls] == [100, 100, 5]
    assert findings == []
    assert skipped == []


def test_query_osv_batch_follows_per_query_pagination(monkeypatch):
    calls = []

    def fake_post(url, payload, timeout):
        calls.append(payload)
        if len(calls) == 1:
            return {
                "results": [
                    {"vulns": [{"id": "OSV-1"}], "next_page_token": "next-a"},
                    {"vulns": [{"id": "OSV-2"}]},
                ]
            }
        return {"results": [{"vulns": [{"id": "OSV-3"}]}, {"vulns": []}]}

    monkeypatch.setattr("sbom_converter.osv._post_json", fake_post)
    entries = [
        {"name": "a", "version": "1.0.0", "purl": "pkg:pypi/a@1.0.0"},
        {"name": "b", "version": "1.0.0", "purl": "pkg:pypi/b@1.0.0"},
    ]
    findings, _ = query_osv_batch(entries)

    assert [x.vulnerability_id for x in findings] == ["OSV-1", "OSV-2", "OSV-3"]
    assert calls[1]["queries"][0]["page_token"] == "next-a"
    assert "page_token" not in calls[1]["queries"][1]


def test_query_osv_batch_skips_missing_purl():
    findings, skipped = query_osv_batch(
        [{"name": "no-purl", "version": "1.0.0", "purl": None}]
    )
    assert findings == []
    assert skipped == ["no-purl"]


def test_legacy_query_osv_is_backwards_compatible(monkeypatch):
    monkeypatch.setattr(
        "sbom_converter.osv._post_json",
        lambda url, payload, timeout: {"results": [{"vulns": [{"id": "OSV-1"}]}]},
    )
    assert query_osv("pkg:pypi/a@1.0.0") == [{"id": "OSV-1", "modified": None}]


def test_query_osv_network_error_raises(monkeypatch):
    def fake_urlopen(req, timeout=15):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr("sbom_converter.osv.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(OsvError, match="OSV.dev lookup failed"):
        # Exercise the fixed HTTPS request helper directly.
        from sbom_converter.osv import _post_json
        _post_json("https://api.osv.dev/v1/querybatch", {"queries": []}, 15)


def test_lookup_vulnerabilities_uses_batch(monkeypatch):
    monkeypatch.setattr(
        "sbom_converter.osv.query_osv_batch",
        lambda entries, timeout=15, batch_size=100, on_batch=None: (
            [OsvFinding("libfoo", "1.2.3", "pkg:pypi/libfoo@1.2.3", "OSV-1", None)],
            [],
        ),
    )
    entries = [{"name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"}]
    statements, skipped = lookup_vulnerabilities(entries)
    assert skipped == []
    assert statements[0]["status"] == "under_investigation"
    assert "exploitability has not been determined by OSV" in statements[0]["status_notes"]


def test_osv_finding_never_asserts_exploitability():
    finding = OsvFinding("example", "1.0.0", "pkg:pypi/example@1.0.0", "GHSA-test")
    assert finding.as_dict()["exploitability"] == "not_determined_by_osv"


def test_osv_report_is_machine_readable():
    report = osv_report(
        [{"name": "example", "purl": "pkg:pypi/example@1.0.0"}],
        [OsvFinding("example", "1.0.0", "pkg:pypi/example@1.0.0", "GHSA-test", None)],
        [],
        100,
    )
    json.dumps(report)
    assert report["endpoint"] == "https://api.osv.dev/v1/querybatch"
    assert report["findings"][0]["vulnerability"] == "GHSA-test"
