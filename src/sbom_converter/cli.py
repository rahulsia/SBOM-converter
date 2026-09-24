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
from .vex import build_vex, validate_vex, validate_vex_input


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
    p.add_argument(
        "--vex",
        help="Path to a JSON file of vulnerability statements; generates an OpenVEX "
        "document (https://openvex.dev) referencing this SBOM's components.",
    )
    p.add_argument("--vex-output", help="Write the generated OpenVEX document to this file (required with --vex).")
    p.add_argument("--vex-author", help="Author name recorded in the VEX document (defaults to the tool's author).")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)
    if not a.input:
        p.error("input is required")
    if a.vex and not a.vex_output:
        p.error("--vex-output is required when --vex is used")
    try:
        doc = load(a.input)
        fmt = detect(doc)
        if a.info:
            print(fmt)
            return 0
        if a.validate and not a.to and not a.vex:
            basic_validate(doc, fmt)
            print(f"OK: {fmt}")
            return 0
        if not a.to and not a.vex:
            p.error("--to is required for conversion (or use --validate, --info, --vex)")
        basic_validate(doc, fmt)
        if a.vex:
            vuln_data = load(a.vex)
            vulnerabilities = validate_vex_input(vuln_data)
            vex_doc = build_vex(doc, vulnerabilities, author=a.vex_author)
            validate_vex(vex_doc)
            Path(a.vex_output).write_text(json.dumps(vex_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"VEX: wrote {len(vex_doc['statements'])} statement(s) to {a.vex_output}")
        if a.to:
            out, rep = convert(doc, a.to, a.strict)
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
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except ValidationError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except ConversionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 4
    except SbomError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 5
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 6
    except Exception as e:  # noqa: BLE001 - top-level CLI handler must not leak a traceback to the user
        print(f"ERROR: unexpected failure while processing input: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
