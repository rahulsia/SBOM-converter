# SBOM Converter

Copyright (c) 2026 Rahul Kumar
Author: Rahul Kumar — rahulk.3477@gmail.com
License: MIT (`SPDX-License-Identifier: MIT`)

A small, dependency-free CLI (and Docker image) that converts JSON Software
Bill of Materials documents between formats:

- **SPDX 2.3 JSON**
- **SPDX 3.x JSON-LD** (3.0.1, and experimental 3.1)
- **CycloneDX JSON** (any spec version as input; 1.7 as output)

It auto-detects the input format, converts it, and produces a machine-readable
warnings report describing anything that couldn't be losslessly mapped (e.g.
an SPDX relationship type with no CycloneDX equivalent).

It can also generate [OpenVEX](https://openvex.dev) vulnerability
exploitability statements referencing the SBOM's components (see
[VEX generation](#vex-generation-openvex)), entirely offline.

## What it does

`sbom-convert` reads a single JSON SBOM file, detects whether it's SPDX 2.3,
SPDX 3.x JSON-LD, or CycloneDX, and converts it to one of the supported
targets below. Conversion is intentionally pragmatic rather than a full
implementation of either spec: fields that map cleanly are carried over,
fields that don't are dropped with a warning rather than silently lost.

### Supported conversion paths

| From ↓ / To → | `cdx-1.7` | `spdx-3.0.1` | `spdx-3.1` |
|---|---|---|---|
| SPDX 2.3 JSON | ✅ | ✅ | ✅ (experimental) |
| CycloneDX JSON (any version) | ✅ | ✅ | ✅ (experimental) |

SPDX 3.1 output is marked experimental — it should be validated against the
exact SPDX 3.1 model/schema your consumer expects before you rely on it.

### What it is not

Built-in validation (`--validate`, and the pre-conversion checks run before
every conversion) is intentionally lightweight and offline-friendly — it
checks that required top-level fields are present and roughly the right
shape, not full JSON Schema/SHACL conformance. For compliance-grade
validation, run the output through the official SPDX or CycloneDX validator
for your target spec version.

## Installation

Requires Python 3.10+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

This installs the `sbom-convert` command on your `PATH`.

## Usage

```
sbom-convert INPUT [--to {spdx-3.0.1,spdx-3.1,cdx-1.7}] [-o OUTPUT]
                    [--report REPORT] [--strict] [--validate] [--info]
                    [--vex VEX] [--vex-output VEX_OUTPUT] [--vex-author AUTHOR]
                    [--version]
```

| Flag | Description |
|---|---|
| `INPUT` | Path to the input SBOM JSON file (required). |
| `--to {spdx-3.0.1,spdx-3.1,cdx-1.7}` | Target format to convert to. Required unless `--validate`, `--info`, or `--vex` is used instead. |
| `-o, --output OUTPUT` | Write the converted SBOM to this file instead of stdout. |
| `--report REPORT` | Write a JSON report of conversion warnings/stats to this file. Without it, a one-line warning count is printed to stderr if there were any. |
| `--strict` | Fail the conversion (non-zero exit) instead of emitting warnings for anything that couldn't be cleanly mapped. |
| `--validate` | Only detect and structurally validate the input; don't convert. Prints `OK: <format>` on success. |
| `--info` | Print the detected input format (e.g. `spdx-2.3`, `cyclonedx-1.6`) and exit. |
| `--vex VEX` | Path to a JSON file of vulnerability statements; generates an [OpenVEX](https://openvex.dev) document referencing this SBOM's components. Can be combined with `--to`. |
| `--vex-output VEX_OUTPUT` | Write the generated OpenVEX document to this file. Required when `--vex` is used. |
| `--vex-author AUTHOR` | Author name recorded in the VEX document. Defaults to the tool's author. |
| `--version` | Print the tool version and exit. |

### Examples

Detect the format of an SBOM:

```bash
sbom-convert input.json --info
# spdx-2.3
```

Validate structure only, without converting:

```bash
sbom-convert input.json --validate
# OK: spdx-2.3
```

Convert an SPDX 2.3 document to SPDX 3.0.1 JSON-LD, writing both the output
and a warnings report:

```bash
sbom-convert input.json --to spdx-3.0.1 -o output.json --report report.json
```

Convert any CycloneDX document to CycloneDX 1.7, printed to stdout:

```bash
sbom-convert input.json --to cdx-1.7
```

Reject the conversion instead of proceeding with mapping warnings:

```bash
sbom-convert input.json --to spdx-3.1 --strict
```

Generate an OpenVEX document from vulnerability statements you supply,
referencing components found in the SBOM:

```bash
sbom-convert input.json --vex vulnerabilities.json --vex-output vex.json
```

Where `vulnerabilities.json` is a JSON array you write yourself (this tool
does not scan for or look up vulnerabilities — see [VEX generation](#vex-generation-openvex) below):

```json
[
  {
    "id": "CVE-2024-12345",
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "products": ["libfoo"]
  },
  {
    "id": "CVE-2024-99999",
    "status": "affected",
    "action_statement": "Upgrade to libbar 2.1.0 or apply the vendor patch."
  }
]
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `2` | Input format could not be identified as SPDX or CycloneDX JSON. |
| `3` | Input failed structural validation (missing required fields, wrong JSON shape, unreadable/invalid JSON file). |
| `4` | Conversion failed (e.g. unsupported source→target pair, or `--strict` rejected warnings). |
| `5` | Other SBOM-related error. |
| `6` | File I/O error. |
| `1` | Unexpected internal error (a bug — please report it). |

## VEX generation (OpenVEX)

`--vex` generates a [OpenVEX](https://github.com/openvex/spec) document — the
minimal, widely-adopted JSON format for stating whether a vulnerability
affects a given component ("exploitability"). It is fully offline: this tool
does **not** scan for vulnerabilities, query any CVE database, or send your
SBOM anywhere. You supply the vulnerability ID and its status; the tool
matches it against components in the SBOM (by name or purl) and emits a
spec-conformant statement.

Input is a JSON array, one object per vulnerability:

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Vulnerability identifier, e.g. a CVE ID. |
| `status` | yes | One of `affected`, `not_affected`, `fixed`, `under_investigation`. |
| `justification` | if `status: not_affected` (or `impact_statement`) | One of `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`. |
| `impact_statement` | alternative to `justification` for `not_affected` | Free-text explanation. |
| `action_statement` | if `status: affected` | What a consumer should do (upgrade, patch, mitigate). |
| `status_notes` | no | Free-text notes. |
| `products` | no | List of component names to scope the statement to. Omit to apply to every component in the SBOM. |
| `timestamp` | no | RFC3339 timestamp; defaults to generation time. |

The generated document is validated against the OpenVEX structural
requirements before being written, and referencing a product name that
doesn't exist in the SBOM is a validation error rather than a silent
mismatch.

For actual vulnerability *discovery* (scanning dependencies against CVE
databases), pair this tool with a scanner such as
[Grype](https://github.com/anchore/grype) or
[Syft](https://github.com/anchore/syft), then feed their findings into a
`vulnerabilities.json` file for `--vex` to turn into an OpenVEX statement.

## Docker

```bash
docker build -t sbom-converter .
docker run --rm -v "$PWD:/data" sbom-converter /data/input.json --to cdx-1.7 -o /data/output.json --report /data/report.json
```

Or with the included Compose file, which mounts the current directory to
`/data` and sets it as the working directory:

```bash
docker compose run --rm sbom-convert input.json --to spdx-3.0.1 -o output.json
```

The container runs as a non-root user.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

pytest -q          # run the test suite
ruff check src tests   # lint
bandit -r src -ll -ii  # SAST
```

CI (`.github/workflows/security.yml`) runs on every pull request: Ruff (via
reviewdog PR comments), pytest, Bandit, pip-audit, Semgrep, Gitleaks, Trivy
(filesystem and built image), and Hadolint against the Dockerfile.

## License

MIT. See `LICENSE`.
