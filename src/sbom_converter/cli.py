# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import ConversionError, SbomError, UnsupportedInput, ValidationError, basic_validate, convert, detect
from .native_vex import analyze_cyclonedx_vex, augment_spdx3_with_cdx_vex
from .osv import lookup_vulnerabilities
from .vex import build_vex, extract_products, validate_vex, validate_vex_input


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {e}")
    except OSError as e:
        raise ValidationError(f"Could not read input file: {e}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="sbom-convert", description="Convert SPDX 2.3 / CycloneDX JSON SBOMs.")
    p.add_argument("input", nargs="?")
    p.add_argument("--to", choices=["spdx-3.0.1", "spdx-3.1", "cdx-1.7"])
    p.add_argument("-o", "--output")
    p.add_argument("--report")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--validate", action="store_true", help="Validate input structure only.")
    p.add_argument("--info", action="store_true", help="Print detected input format.")
    p.add_argument("--analyze-vex", action="store_true", help="Analyze embedded CycloneDX vulnerability/VEX assertions without changing their producer-supplied status.")
    p.add_argument("--vex-report", help="Write embedded CycloneDX VEX analysis summary as JSON.")
    p.add_argument("--vex", action="store_true", help="Generate an OpenVEX document. By default queries OSV.dev using component purls; use --vex-input for offline supplied assertions.")
    p.add_argument("--vex-input", help="Path to a JSON file of vulnerability statements supplied by the user.")
    p.add_argument("--vex-output", help="Write generated OpenVEX to this file (required with --vex).")
    p.add_argument("--vex-author", help="Author recorded in generated OpenVEX.")
    p.add_argument("--vex-timeout", type=int, default=15, help="OSV.dev timeout in seconds (default: 15).")
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
    try:
        doc = load(a.input)
        fmt = detect(doc)
        if a.info:
            print(fmt); return 0
        if a.validate and not a.to and not a.vex and not a.analyze_vex:
            basic_validate(doc, fmt); print(f"OK: {fmt}"); return 0
        if not a.to and not a.vex and not a.analyze_vex:
            p.error("--to is required for conversion (or use --validate, --info, --vex, --analyze-vex)")
        basic_validate(doc, fmt)

        if a.analyze_vex:
            if not fmt.startswith("cyclonedx-"):
                raise ValidationError("--analyze-vex currently analyzes embedded CycloneDX vulnerability/VEX data.")
            summary = analyze_cyclonedx_vex(doc)
            text = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
            if a.vex_report:
                Path(a.vex_report).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)

        if a.vex:
            if a.vex_input:
                vulnerabilities = validate_vex_input(load(a.vex_input))
            else:
                entries = extract_products(doc)
                if not entries:
                    raise ValidationError("No identifiable components/packages found in the SBOM to query.")
                print(f"VEX: querying OSV.dev for {len(entries)} component(s)...", file=sys.stderr)
                raw, skipped = lookup_vulnerabilities(entries, timeout=a.vex_timeout)
                if skipped:
                    print(f"VEX: skipped {len(skipped)} component(s) without a package URL (purl): {', '.join(skipped)}", file=sys.stderr)
                vulnerabilities = validate_vex_input(raw) if raw else []
            if vulnerabilities:
                vex_doc = build_vex(doc, vulnerabilities, author=a.vex_author)
                validate_vex(vex_doc)
                Path(a.vex_output).write_text(json.dumps(vex_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                print(f"VEX: wrote {len(vex_doc['statements'])} statement(s) to {a.vex_output}")
            else:
                print("VEX: no vulnerabilities found; nothing written.")

        if a.to:
            out, rep = convert(doc, a.to, a.strict)
            # Preserve embedded CycloneDX VEX semantically when targeting SPDX 3.
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
                print(f"WARNING: conversion completed with {len(rep.warnings)} warning(s). Use --report for details.", file=sys.stderr)
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
