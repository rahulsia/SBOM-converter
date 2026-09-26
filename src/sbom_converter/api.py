# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""Optional FastAPI adapter over the SBOM Converter service layer."""
from __future__ import annotations

from typing import Any


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as exc:
        raise RuntimeError(
            "FastAPI is optional. Install with: pip install 'sbom-converter-rahul[api]'"
        ) from exc

    from . import __version__
    from .service import analyze_vex, convert_sbom, scan_vulnerabilities

    app = FastAPI(
        title="SBOM Converter API",
        version=__version__,
        description="Convert SPDX/CycloneDX SBOMs and optionally scan OSV/NVD and analyze VEX.",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/convert")
    def convert_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return convert_sbom(payload["sbom"], payload["target"], bool(payload.get("strict", False)))
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"Missing field: {exc.args[0]}") from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/scan")
    def scan_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return scan_vulnerabilities(
                payload["sbom"],
                sources=payload.get("sources", ["osv", "nvd"]),
                osv_batch_size=int(payload.get("osvBatchSize", 100)),
                osv_timeout=int(payload.get("osvTimeout", 15)),
                nvd_timeout=int(payload.get("nvdTimeout", 20)),
                nvd_api_key=payload.get("nvdApiKey"),
                nvd_delay=payload.get("nvdDelay"),
            )
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"Missing field: {exc.args[0]}") from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/vex/analyze")
    def analyze_vex_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return analyze_vex(payload["sbom"])
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"Missing field: {exc.args[0]}") from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def run():
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "Uvicorn is optional. Install with: pip install 'sbom-converter-rahul[api]'"
        ) from exc
    uvicorn.run("sbom_converter.api:create_app", host="0.0.0.0", port=8000, factory=True)
