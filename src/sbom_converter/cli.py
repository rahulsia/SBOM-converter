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


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="sbom-convert",
        description="Convert SPDX 2.3 / CycloneDX JSON SBOMs and optionally analyze OSV/VEX."
    )
    p.add_argument("input", nargs="?")
    p.add_argument("--to", choices=["spdx-3.0.1", "spdx-3.1", "cdx-1.7"])
    p.add_argument("-o", "--output")
    p.add_argument("--report")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--validate", action="store_true", help="Validate input structure only.")
    p.add_argument("--info", action="store_true", help="Print detected input format.")

    p.add_argument(
        "--osv-scan",
        action="store_true",
        help="Query OSV.dev over HTTPS using versioned component PURLs; does not modify the SBOM."
    )
    p.add_argument("--osv-report", help="Write OSV vulnerability report as JSON.")
    p.add_argument(
        "--osv-batch-size",
        type=int,
        default=100,
        help="PURLs per OSV /v1/querybatch request (default: 100)."
    )

    p.add_argument(
        "--analyze-vex",
        action="store_true",
        help="Analyze embedded CycloneDX vulnerability/VEX assertions without changing them."
    )
    p.add_argument("--vex-report", help="Write embedded VEX analysis summary as JSON.")
    p.add_argument(
        "--security-report",
        help="Write combined OSV findings and VEX correlation as JSON."
    )

    p.add_argument(
        "--vex",
        action="store_true",
        help="Generate OpenVEX. With no --vex-input, OSV findings become under_investigation "
             "statements; this does not assert exploitability."
    )
    p.add_argument("--vex-input", help="Path to supplied VEX statement JSON.")
    p.add_argument("--vex-output", help="Write generated OpenVEX to this file.")
    p.add_argument("--vex-author", help="Author recorded in generated OpenVEX.")
    p.add_argument("--osv-timeout", type=int, default=15, help="OSV HTTPS timeout in seconds.")
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
    if a.osv_report and not a.osv_scan:
        p.error("--osv-report requires --osv-scan")
    if a.security_report and not (a.osv_scan or a.analyze_vex):
        p.error("--security-report requires --osv-scan and/or --analyze-vex")
    if a.osv_batch_size < 1:
        p.error("--osv-batch-size must be >= 1")

    try:
        doc = load(a.input)
        fmt = detect(doc)
        basic_validate(doc, fmt)

        if a.info:
            print(fmt)
            return 0
        if a.validate and not any((a.to, a.vex, a.analyze_vex, a.osv_scan)):
            print(f"OK: {fmt}")
            return 0
        if not any((a.to, a.vex, a.analyze_vex, a.osv_scan)):
            p.error("--to is required for conversion (or use --validate, --info, --vex, --analyze-vex, --osv-scan)")

        entries = extract_products(doc)
        osv_findings = []
        osv_result = None

        if a.osv_scan:
            if not entries:
                raise ValidationError("No identifiable components/packages found in the SBOM to query.")
            purl_count = len({e.get("purl") for e in entries if e.get("purl")})
            print(
                f"OSV: querying {purl_count} unique versioned PURL(s) via "
                f"HTTPS /v1/querybatch (batch size {a.osv_batch_size})...",
                file=sys.stderr,
            )
            osv_result = scan_osv(
                doc,
                timeout=a.osv_timeout,
                batch_size=a.osv_batch_size,
            )
            osv_findings = osv_result.get("findings", [])
            if a.osv_report:
                Path(a.osv_report).write_text(
                    json.dumps(osv_result, indent=2, ensure_ascii=False) + "
",
                    encoding="utf-8",
                )
                print(f"OSV: wrote {len(osv_findings)} finding(s) to {a.osv_report}")
            else:
                print(json.dumps(osv_result, indent=2, ensure_ascii=False))

        vex_data = None
        if a.analyze_vex:
            if not fmt.startswith("cyclonedx-"):
                raise ValidationError("--analyze-vex currently analyzes embedded CycloneDX vulnerability/VEX data.")
            vex_data = analyze_cyclonedx_vex(doc)
            if a.vex_report:
                Path(a.vex_report).write_text(
                    json.dumps(vex_data, indent=2, ensure_ascii=False) + "
",
                    encoding="utf-8",
                )
            else:
                print(json.dumps(vex_data, indent=2, ensure_ascii=False))

        if a.security_report:
            embedded = vex_data
            if embedded is None:
                embedded = (
                    analyze_cyclonedx_vex(doc)
                    if fmt.startswith("cyclonedx-")
                    else {
                        "totalVulnerabilities": 0,
                        "states": {},
                        "justifications": {},
                        "responses": {},
                        "affectedComponentRefs": [],
                        "warnings": [{
                            "code": "NO_EMBEDDED_VEX_MODEL",
                            "message": "SPDX 2.3 input has no native VEX analysis object in this converter."
                        }],
                    }
                )
            security = {
                "inputFormat": fmt,
                "osv": osv_result or {"findings": []},
                "embeddedVex": embedded,
                "correlation": osv_findings,
            }
            Path(a.security_report).write_text(
                json.dumps(security, indent=2, ensure_ascii=False) + "
",
                encoding="utf-8",
            )

        if a.vex:
            if a.vex_input:
                vulnerabilities = validate_vex_input(load(a.vex_input))
            else:
                if not osv_result:
                    # Preserve backwards compatibility, but still use querybatch.
                    entries = extract_products(doc)
                    raw, skipped = lookup_vulnerabilities(
                        entries,
                        timeout=a.osv_timeout,
                        batch_size=a.osv_batch_size,
                    )
                    vulnerabilities = validate_vex_input(raw) if raw else []
                else:
                    vulnerabilities = validate_vex_input([
                        {
                            "id": f["id"],
                            "status": "under_investigation",
                            "status_notes": (
                                f"Detected by OSV.dev for {f['purl']}; "
                                "exploitability has not been determined by OSV."
                            ),
                            "products": [f["component"]],
                        }
                        for f in osv_findings
                    ]) if osv_findings else []

            if vulnerabilities:
                vex_doc = build_vex(doc, vulnerabilities, author=a.vex_author)
                validate_vex(vex_doc)
                Path(a.vex_output).write_text(
                    json.dumps(vex_doc, indent=2, ensure_ascii=False) + "
",
                    encoding="utf-8",
                )
                print(f"VEX: wrote {len(vex_doc['statements'])} statement(s) to {a.vex_output}")
            else:
                print("VEX: no vulnerabilities found; nothing written.")

        if a.to:
            out, rep = convert(doc, a.to, a.strict)
            if fmt.startswith("cyclonedx-") and a.to in ("spdx-3.0.1", "spdx-3.1") and doc.get("vulnerabilities"):
                augment_spdx3_with_cdx_vex(doc, out, rep)
            text = json.dumps(out, indent=2, ensure_ascii=False) + "
"
            if a.output:
                Path(a.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            if a.report:
                Path(a.report).write_text(rep.json() + "
", encoding="utf-8")
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
