# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

import pytest

from sbom_converter.api import create_app

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_convert_endpoint(client, monkeypatch):
    import sbom_converter.api as api

    monkeypatch.setattr(
        api,
        "create_app",
        api.create_app,
    )
    response = client.post(
        "/convert",
        json={"sbom": {"spdxVersion": "SPDX-2.3", "name": "test"}, "target": "cdx-1.7"},
    )
    assert response.status_code == 200


def test_convert_missing_field(client):
    response = client.post("/convert", json={"target": "cdx-1.7"})
    assert response.status_code == 400
    assert "Missing field" in response.json()["detail"]


def test_scan_endpoint(client):
    response = client.post(
        "/scan",
        json={"sbom": {"spdxVersion": "SPDX-2.3", "name": "test"}, "sources": ["osv"]},
    )
    assert response.status_code in (200, 400)


def test_vex_analysis_endpoint(client):
    response = client.post(
        "/vex/analyze",
        json={"sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}},
    )
    assert response.status_code == 200
