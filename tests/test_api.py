# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

import pytest

pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture()
def app(monkeypatch):
    import sbom_converter.service as service

    monkeypatch.setattr(
        service,
        "convert_sbom",
        lambda document, target, strict=False: {
            "inputFormat": "spdx-2.3",
            "targetFormat": target,
            "sbom": document,
            "report": {"warnings": []},
        },
    )
    monkeypatch.setattr(
        service,
        "scan_vulnerabilities",
        lambda document, sources=("osv", "nvd"), **kwargs: {
            "inputFormat": "spdx-2.3",
            "sources": {source: {"vulnerabilityMatches": 0} for source in sources},
            "findings": [],
        },
    )
    monkeypatch.setattr(
        service,
        "analyze_vex",
        lambda document: {"totalVulnerabilities": 0, "states": {}, "warnings": []},
    )
    from sbom_converter.api import create_app
    return create_app()


@pytest.fixture()
def client(app):
    return TestClient(app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_convert_endpoint(client):
    response = client.post(
        "/convert",
        json={"sbom": {"spdxVersion": "SPDX-2.3", "name": "test"}, "target": "cdx-1.7"},
    )
    assert response.status_code == 200
    assert response.json()["targetFormat"] == "cdx-1.7"


def test_convert_missing_field(client):
    response = client.post("/convert", json={"target": "cdx-1.7"})
    assert response.status_code == 400
    assert "Missing field" in response.json()["detail"]


def test_scan_endpoint(client):
    response = client.post(
        "/scan",
        json={"sbom": {"spdxVersion": "SPDX-2.3", "name": "test"}, "sources": ["osv", "nvd"]},
    )
    assert response.status_code == 200
    assert set(response.json()["sources"]) == {"osv", "nvd"}


def test_vex_analysis_endpoint(client):
    response = client.post(
        "/vex/analyze",
        json={"sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}},
    )
    assert response.status_code == 200
