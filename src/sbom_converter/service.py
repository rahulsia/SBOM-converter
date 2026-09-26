# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""Reusable application service layer for SBOM conversion, scanning and VEX."""
from __future__ import annotations

from .core import basic_validate, convert, detect
from .native_vex import analyze_cyclonedx_vex, augment_spdx3_with_cdx_vex
from .nvd import extract_cpe_entries, nvd_report, scan_nvd
from .osv_scan import scan_osv
from .vex import build_vex, validate_vex


def convert_sbom(document: dict, target: str, strict: bool = False) -> dict:
    output, report = convert(document, target, strict)
    fmt = detect(document)
    if fmt.startswith("cyclonedx-") and target in ("spdx-3.0.1", "spdx-3.1") and document.get("vulnerabilities"):
        augment_spdx3_with_cdx_vex(document, output, report)
    return {
        "inputFormat": fmt,
        "targetFormat": target,
        "sbom": output,
        "report": {
            "inputFormat": report.input_format,
            "targetFormat": report.target_format,
            "stats": report.stats,
            "warnings": [{"code": w.code, "message": w.message, "path": w.path} for w in report.warnings],
        },
    }


def analyze_vex(document: dict) -> dict:
    fmt = detect(document)
    basic_validate(document, fmt)
    if not fmt.startswith("cyclonedx-"):
        raise ValueError("Embedded VEX analysis currently supports CycloneDX input.")
    return analyze_cyclonedx_vex(document)


def scan_vulnerabilities(
    document: dict,
    sources=("osv", "nvd"),
    *,
    osv_timeout: int = 15,
    osv_batch_size: int = 100,
    nvd_timeout: int = 20,
    nvd_api_key: str | None = None,
    nvd_delay: float | None = None,
) -> dict:
    fmt = detect(document)
    basic_validate(document, fmt)
    sources = {s.lower() for s in sources}
    invalid = sources - {"osv", "nvd"}
    if invalid:
        raise ValueError(f"Unsupported vulnerability source(s): {sorted(invalid)}")

    result = {"inputFormat": fmt, "sources": {}, "findings": []}

    if "osv" in sources:
        osv_result = scan_osv(document, timeout=osv_timeout, batch_size=osv_batch_size)
        result["sources"]["osv"] = osv_result
        result["findings"].extend(
            {
                "source": "OSV.dev",
                "id": f["id"],
                "component": f["component"],
                "version": f["version"],
                "purl": f["purl"],
                "vexStatus": f.get("vexStatus", "unassessed"),
                "exploitability": "not_determined_by_osv",
            }
            for f in osv_result.get("findings", [])
        )

    if "nvd" in sources:
        entries = extract_cpe_entries(document)
        raw, skipped = scan_nvd(entries, timeout=nvd_timeout, api_key=nvd_api_key, min_delay=nvd_delay)
        result["sources"]["nvd"] = nvd_report(entries, raw, skipped, api_key_used=bool(nvd_api_key))
        result["findings"].extend({**f.as_dict(), "source": "NVD/NIST"} for f in raw)

    return result


def generate_vex_from_findings(document: dict, findings: list[dict], author: str | None = None) -> dict:
    statements = []
    seen = set()
    for finding in findings:
        key = (finding["id"], finding.get("component"))
        if key in seen:
            continue
        seen.add(key)
        statements.append({
            "id": finding["id"],
            "status": finding.get("status", "under_investigation"),
            "status_notes": finding.get(
                "status_notes",
                f"Detected by {finding.get('source', 'vulnerability provider')}; exploitability has not been independently determined.",
            ),
            "products": [finding["component"]] if finding.get("component") else [],
        })
    if not statements:
        raise ValueError("At least one vulnerability finding is required to generate VEX.")
    vex = build_vex(document, statements, author=author)
    validate_vex(vex)
    return vex
