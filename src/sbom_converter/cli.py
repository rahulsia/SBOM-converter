# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import (
    ConversionError,
    SbomError,
    UnsupportedInput,
    ValidationError,
    basic_validate,
    convert,
    detect,
)
from .native_vex import analyze_cyclonedx_vex, augment_spdx3_with_cdx_vex
from .nvd import extract_cpe_entries, nvd_report, scan_nvd
from .osv import lookup_vulnerabilities
from .osv_scan import scan_osv
from .vex import build_vex, extract_products, validate_vex, validate_vex_input


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {e}")
    except OSError as e:
        raise ValidationError(f"Could not read input file: {e}")


def _dedupe_vex_inputs(items):
    seen = set()
    result = []
    for item in items:
        key = (item.get("id"), tuple(sorted(item.get("products") or [])))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="sbom-convert",
        description="Convert SPDX 2.3 / CycloneDX JSON SBOMs and optionally analyze OSV/NVD/VEX."
    )
    p.add_argument("input", nargs="?")
    p.add_argument("--to", choices=["spdx-3.0.1", "spdx-3.1", "cdx-1.7"])
    p.add_argument("-o", "--output")
    p.add_argument("--report")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--validate", action="store_true", help="Validate input structure only.")
    p.add_argument("--info", action="store_true", help="Print detected input format.")

    p.add_argument(
        "--vuln-source",
        choices=["osv", "nvd", "both"],
        help="Optional vulnerability source. Selecting nvd uses CPEs; osv uses versioned PURLs."
    )
    p.add_argument(
        "--osv-scan",
        action="store_true",
        help="Backward-compatible alias for --vuln-source osv."
    )
    p.add_argument("--osv-report", help="Write OSV vulnerability report as JSON.")
    p.add_argument("--osv-batch-size", type=int, default=100,
                   help="PURLs per OSV /v1/querybatch request (default: 100).")

    p.add_argument("--nvd-report", help="Write NVD vulnerability report as JSON.")
    p.add_argument("--nvd-api-key", help="Optional NVD API key; otherwise use unauthenticated rate limits.")
    p.add_argument("--nvd-timeout", type=int, default=20, help="NVD HTTPS timeout in seconds.")
    p.add_argument("--nvd-delay", type=float, default=None,
                   help="Minimum delay between NVD paginated requests/CPE queries. "
                        "Defaults are conservative for API-key and unauthenticated use.")

    p.add_argument("--analyze-vex", action="store_true",
                   help="Analyze embedded CycloneDX vulnerability/VEX assertions without changing them.")
    p.add_argument("--vex-report", help="Write embedded VEX analysis summary as JSON.")
    p.add_argument("--security-report",
                   help="Write combined vulnerability-source findings and VEX correlation as JSON.")

    p.add_argument("--vex", action="store_true",
                   help="Generate OpenVEX. Without --vex-input, vulnerability-source findings become "
                        "under_investigation statements; this does not assert exploitability.")
    p.add_argument("--vex-input", help="Path to supplied VEX statement JSON.")
    p.add_argument("--vex-output", help="Write generated OpenVEX to this file.")
    p.add_argument("--vex-author", help="Author recorded in generated OpenVEX.")

    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)

    if not a.input:
        p.error("input is required")
    if a.vex and not a.vex_output:
        p.error("--vex-output is required when --vex is used")
    if a.vex_input and not a.vex:
        p.error("--vex-input requires --vex")
    if a.vex_report and not a.analyze_vex:
        p.error("--vex-report requires --analyze-vex")
    if a.osv_report and not (a.osv_scan or a.vuln_source in ("osv", "both")):
        p.error("--osv-report requires an OSV-enabled vulnerability source")
    if a.nvd_report and a.vuln_source not in ("nvd", "both"):
        p.error("--nvd-report requires --vuln-source nvd or both")
    if a.security_report and not (a.osv_scan or a.vuln_source or a.analyze_vex):
        p.error("--security-report requires a vulnerability source and/or --analyze-vex")
    if a.osv_batch_size < 1:
        p.error("--osv-batch-size must be >= 1")
    if a.nvd_timeout < 1:
        p.error("--nvd-timeout must be >= 1")
    if a.nvd_delay is not None and a.nvd_delay < 0:
        p.error("--nvd-delay must be >= 0")

    try:
        doc = load(a.input)
        fmt = detect(doc)
        basic_validate(doc, fmt)

        if a.info:
            print(fmt)
            return 0
        if a.validate and not any((a.to, a.vex, a.analyze_vex, a.osv_scan, a.vuln_source)):
            print(f"OK: {fmt}")
            return 0
        if not any((a.to, a.vex, a.analyze_vex, a.osv_scan, a.vuln_source)):
            p.error("--to is required for conversion (or use --validate, --info, --vuln-source, --vex, --analyze-vex)")

        source = a.vuln_source
        if a.osv_scan:
            source = "both" if source == "nvd" else "osv"
        if source == "both":
            osv_enabled = True
            nvd_enabled = True
        else:
            osv_enabled = source == "osv"
            nvd_enabled = source == "nvd"

        entries = extract_products(doc)
        osv_result = None
        nvd_result = None
        osv_findings = []
        nvd_findings = []

        if osv_enabled:
            if not entries:
                raise ValidationError("No identifiable components/packages found in the SBOM for OSV lookup.")
            osv_result = scan_osv(doc, timeout=15, batch_size=a.osv_batch_size)
            osv_findings = osv_result.get("findings", [])
            if a.osv_report:
                Path(a.osv_report).write_text(
                    json.dumps(osv_result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            else:
                print(json.dumps(osv_result, indent=2, ensure_ascii=False))

        if nvd_enabled:
            cpe_entries = extract_cpe_entries(doc)
            if not cpe_entries:
                raise ValidationError("No CPE identifiers found in the SBOM for NVD lookup.")
            print(
                f"NVD: querying {len({x['cpe'] for x in cpe_entries})} unique CPE(s) via "
                "HTTPS CVE 2.0 API...",
                file=sys.stderr,
            )

            def progress(idx, total, cpe):
                print(f"NVD: CPE {idx}/{total}: {cpe}", file=sys.stderr)

            raw, skipped = scan_nvd(
                cpe_entries,
                timeout=a.nvd_timeout,
                api_key=a.nvd_api_key,
                min_delay=a.nvd_delay,
                on_cpe=progress,
            )
            nvd_findings = [x.as_dict() for x in raw]
            nvd_result = nvd_report(
                cpe_entries, raw, skipped, api_key_used=bool(a.nvd_api_key)
            )
            if a.nvd_report:
                Path(a.nvd_report).write_text(
                    json.dumps(nvd_result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            else:
                print(json.dumps(nvd_result, indent=2, ensure_ascii=False))

        vex_data = None
        if a.analyze_vex:
            if not fmt.startswith("cyclonedx-"):
                raise ValidationError("--analyze-vex currently analyzes embedded CycloneDX vulnerability/VEX data.")
            vex_data = analyze_cyclonedx_vex(doc)
            if a.vex_report:
                Path(a.vex_report).write_text(
                    json.dumps(vex_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            else:
                print(json.dumps(vex_data, indent=2, ensure_ascii=False))

        # Correlate source findings with embedded CycloneDX VEX by vulnerability ID.
        correlations = []
        embedded_by_id = {}
        if fmt.startswith("cyclonedx-"):
            for vuln in doc.get("vulnerabilities", []) or []:
                if vuln.get("id"):
                    embedded_by_id[vuln["id"]] = {
                        "state": (vuln.get("analysis") or {}).get("state", "unassessed"),
                        "justification": (vuln.get("analysis") or {}).get("justification"),
                        "response": (vuln.get("analysis") or {}).get("response", []),
                        "detail": (vuln.get("analysis") or {}).get("detail"),
                    }

        source_findings = []
        for f in osv_findings:
            source_findings.append({
                "source": "OSV.dev",
                "id": f["id"],
                "component": f["component"],
                "version": f["version"],
                "purl": f["purl"],
                "vexStatus": embedded_by_id.get(f["id"], {}).get("state", "unassessed"),
                "exploitability": "not_determined_by_osv",
            })
        for f in nvd_findings:
            source_findings.append({
                "source": "NVD/NIST",
                "id": f["vulnerability"],
                "component": f["component"],
                "version": f["version"],
                "cpe": f["cpe"],
                "vexStatus": embedded_by_id.get(f["vulnerability"], {}).get("state", "unassessed"),
                "exploitability": "not_determined_by_nvd",
                "cvss": f["cvss"],
            })

        if a.security_report:
            Path(a.security_report).write_text(
                json.dumps({
                    "inputFormat": fmt,
                    "sources": {
                        "osv": osv_result,
                        "nvd": nvd_result,
                    },
                    "embeddedVex": vex_data if vex_data is not None else (
                        analyze_cyclonedx_vex(doc) if fmt.startswith("cyclonedx-") else {
                            "totalVulnerabilities": 0,
                            "states": {},
                            "justifications": {},
                            "responses": {},
                            "affectedComponentRefs": [],
                            "warnings": [{
                                "code": "NO_EMBEDDED_VEX_MODEL",
                                "message": "SPDX 2.3 input has no embedded CycloneDX VEX analysis object."
                            }]
                        }
                    ),
                    "findings": source_findings,
                    "note": (
                        "OSV/NVD matches identify known vulnerability records. "
                        "Neither source independently establishes product exploitability."
                    ),
                }, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        if a.vex:
            if a.vex_input:
                vulnerabilities = validate_vex_input(load(a.vex_input))
            else:
                generated = []
                for f in source_findings:
                    generated.append({
                        "id": f["id"],
                        "status": "under_investigation",
                        "status_notes": (
                            f"Detected by {f['source']} for "
                            f"{f.get('purl') or f.get('cpe')}; "
                            "exploitability has not been determined by the vulnerability source."
                        ),
                        "products": [f["component"]],
                    })
                vulnerabilities = validate_vex_input(_dedupe_vex_inputs(generated)) if generated else []

            if vulnerabilities:
                vex_doc = build_vex(doc, vulnerabilities, author=a.vex_author)
                validate_vex(vex_doc)
                Path(a.vex_output).write_text(
                    json.dumps(vex_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                print(f"VEX: wrote {len(vex_doc['statements'])} statement(s) to {a.vex_output}")
            else:
                print("VEX: no vulnerability findings available; no VEX document generated.")

        if a.to:
            out, rep = convert(doc, a.to, a.strict)
            if fmt.startswith("cyclonedx-") and a.to in ("spdx-3.0.1", "spdx-3.1") and doc.get("vulnerabilities"):
                augment_spdx3_with_cdx_vex(doc, out, rep)
            text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
            if a.output:
                Path(a.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            if a.report:
                Path(a.report).write_text(rep.json() + "\n", encoding="utf-8")
            elif rep.warnings:
                print(
                    f"WARNING: conversion completed with {len(rep.warnings)} warning(s). "
                    "Use --report for details.",
                    file=sys.stderr,
                )
        return 0
    except UnsupportedInput as e:
        print(f"ERROR: {e}", file=sys.stderr); return 2
    except ValidationError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 3
    except ConversionError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 4
    except SbomError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 5
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 6
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: unexpected failure while processing input: {e}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
