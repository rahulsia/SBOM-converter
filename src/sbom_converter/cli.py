# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__
from .core import detect, basic_validate, convert, SbomError, UnsupportedInput, ValidationError, ConversionError

def load(path):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e: raise ValidationError(f"Invalid JSON: {e}")

def main(argv=None):
    p=argparse.ArgumentParser(prog="sbom-convert",description="Convert SPDX 2.3 / CycloneDX JSON SBOMs.")
    p.add_argument("input",nargs="?")
    p.add_argument("--to",choices=["spdx-3.0.1","spdx-3.1","cdx-1.7"])
    p.add_argument("-o","--output")
    p.add_argument("--report")
    p.add_argument("--strict",action="store_true")
    p.add_argument("--validate",action="store_true",help="Validate input structure only.")
    p.add_argument("--info",action="store_true",help="Print detected input format.")
    p.add_argument("--version",action="version",version=__version__)
    a=p.parse_args(argv)
    if not a.input: p.error("input is required")
    try:
        doc=load(a.input); fmt=detect(doc)
        if a.info: print(fmt); return 0
        if a.validate and not a.to:
            basic_validate(doc,fmt); print(f"OK: {fmt}"); return 0
        if not a.to: p.error("--to is required for conversion")
        out,rep=convert(doc,a.to,a.strict)
        text=json.dumps(out,indent=2,ensure_ascii=False)+"\n"
        if a.output: Path(a.output).write_text(text,encoding="utf-8")
        else: sys.stdout.write(text)
        if a.report: Path(a.report).write_text(rep.json()+"\n",encoding="utf-8")
        elif rep.warnings: print(f"WARNING: conversion completed with {len(rep.warnings)} warning(s). Use --report for details.",file=sys.stderr)
        return 0
    except UnsupportedInput as e: print(f"ERROR: {e}",file=sys.stderr); return 2
    except ValidationError as e: print(f"ERROR: {e}",file=sys.stderr); return 3
    except ConversionError as e: print(f"ERROR: {e}",file=sys.stderr); return 4
    except SbomError as e: print(f"ERROR: {e}",file=sys.stderr); return 5

if __name__=="__main__": raise SystemExit(main())
