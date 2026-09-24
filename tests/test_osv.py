# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
import json
import urllib.error

import pytest

from sbom_converter.osv import OsvError, lookup_vulnerabilities, query_osv


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_query_osv_returns_vulns(monkeypatch):
    def fake_urlopen(req, timeout=15):
        assert req.full_url == "https://api.osv.dev/v1/query"
        body = json.loads(req.data.decode("utf-8"))
        assert body == {"package": {"purl": "pkg:pypi/libfoo@1.2.3"}}
        return FakeResponse({"vulns": [{"id": "OSV-2024-1", "summary": "A bad bug."}]})

    monkeypatch.setattr("sbom_converter.osv.urllib.request.urlopen", fake_urlopen)
    vulns = query_osv("pkg:pypi/libfoo@1.2.3")
    assert vulns == [{"id": "OSV-2024-1", "summary": "A bad bug."}]


def test_query_osv_empty_result(monkeypatch):
    monkeypatch.setattr("sbom_converter.osv.urllib.request.urlopen", lambda req, timeout=15: FakeResponse({}))
    assert query_osv("pkg:pypi/libfoo@1.2.3") == []


def test_query_osv_network_error_raises(monkeypatch):
    def fake_urlopen(req, timeout=15):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr("sbom_converter.osv.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(OsvError, match="OSV.dev lookup failed"):
        query_osv("pkg:pypi/libfoo@1.2.3")


def test_query_osv_invalid_json_raises(monkeypatch):
    class BadResponse:
        def read(self):
            return b"not json"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("sbom_converter.osv.urllib.request.urlopen", lambda req, timeout=15: BadResponse())
    with pytest.raises(OsvError, match="invalid JSON"):
        query_osv("pkg:pypi/libfoo@1.2.3")


def test_lookup_vulnerabilities_skips_entries_without_purl(monkeypatch):
    monkeypatch.setattr("sbom_converter.osv.query_osv", lambda purl, timeout=15: [])
    entries = [{"name": "libfoo", "version": "1.2.3", "purl": None}]
    statements, skipped = lookup_vulnerabilities(entries)
    assert statements == []
    assert skipped == ["libfoo"]


def test_lookup_vulnerabilities_builds_statements(monkeypatch):
    def fake_query(purl, timeout=15):
        return [{"id": "OSV-2024-1", "summary": "A bad bug."}]

    monkeypatch.setattr("sbom_converter.osv.query_osv", fake_query)
    entries = [{"name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"}]
    statements, skipped = lookup_vulnerabilities(entries)
    assert skipped == []
    assert len(statements) == 1
    stmt = statements[0]
    assert stmt["id"] == "OSV-2024-1"
    assert stmt["status"] == "under_investigation"
    assert "A bad bug." in stmt["status_notes"]
    assert stmt["products"] == ["libfoo"]


def test_lookup_vulnerabilities_dedupes_same_vuln_and_product(monkeypatch):
    monkeypatch.setattr("sbom_converter.osv.query_osv", lambda purl, timeout=15: [{"id": "OSV-2024-1"}, {"id": "OSV-2024-1"}])
    entries = [{"name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"}]
    statements, _ = lookup_vulnerabilities(entries)
    assert len(statements) == 1


def test_lookup_vulnerabilities_calls_on_query_callback(monkeypatch):
    monkeypatch.setattr("sbom_converter.osv.query_osv", lambda purl, timeout=15: [])
    seen = []
    entries = [{"name": "libfoo", "version": "1.2.3", "purl": "pkg:pypi/libfoo@1.2.3"}]
    lookup_vulnerabilities(entries, on_query=seen.append)
    assert seen == entries
