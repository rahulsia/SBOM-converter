# SBOM Converter

Copyright (c) 2026 Rahul Kumar
Author: Rahul Kumar — rahulk.3477@gmail.com
License: MIT (`SPDX-License-Identifier: MIT`)

A small CLI (and Docker image) for pragmatic JSON SBOM conversion and optional vulnerability/VEX analysis.

## Supported formats

- SPDX 2.3 JSON
- SPDX 3.0.1 JSON-LD
- SPDX 3.1 JSON-LD (experimental)
- CycloneDX JSON, including 1.6 input and 1.7 output

## Operating modes

### 1. Pure conversion — offline

Conversion does not contact external services.

```bash
sbom-convert input.json --to cdx-1.7 -o output.json
sbom-convert input.json --to spdx-3.0.1 -o output.json
sbom-convert input.json --to spdx-3.1 -o output.json
```

### 2. Embedded VEX analysis — offline

For CycloneDX input, `--analyze-vex` reads the SBOM's existing vulnerability analysis fields without inventing a status.

```bash
sbom-convert input.json \
  --analyze-vex \
  --vex-report vex-report.json
```

### 3. OSV vulnerability scan — network opt-in

`--osv-scan` explicitly enables HTTPS requests to OSV.dev. Only versioned component PURLs are sent; the full SBOM is not uploaded.

The implementation uses OSV's `POST /v1/querybatch` endpoint, batching PURLs and following per-query pagination tokens.

```bash
sbom-convert input.json \
  --osv-scan \
  --osv-report osv-report.json
```

For a large BOM:

```bash
sbom-convert input.json \
  --osv-scan \
  --osv-batch-size 100 \
  --osv-report osv-report.json
```

The report records the OSV endpoint, batch size, PURLs queried, skipped components, vulnerability IDs, and modified timestamps.

OSV matches are reported as known package/version vulnerability findings. **They do not establish product exploitability.**

### 4. OSV + VEX correlation

```bash
sbom-convert input.json \
  --osv-scan \
  --analyze-vex \
  --security-report security-report.json
```

For each OSV match the report correlates any existing embedded CycloneDX VEX assertion:

```text
OSV match
   |
   +-- matching embedded VEX --> preserve producer-supplied state
   |
   +-- no VEX assertion ------> unassessed
```

The converter never changes an OSV match into `exploitable` merely because OSV reports the package/version as vulnerable.

### 5. OpenVEX generation

Manual/supplied VEX remains fully offline:

```bash
sbom-convert input.json \
  --vex \
  --vex-input vulnerabilities.json \
  --vex-output vex.json
```

For backwards compatibility, `--vex` without `--vex-input` can use OSV findings as `under_investigation` statements. Those statements explicitly state that exploitability has not been determined by OSV.

## Why OSV is separate from VEX

OSV provides known vulnerability intelligence for open-source packages and versions. VEX provides product-contextual assessment of whether a vulnerability affects a particular product.

Therefore:

```text
PURL/version
     |
     v
OSV.dev
     |
     v
known vulnerability
     |
     +---- existing VEX ----> affected / not_affected / fixed / etc.
     |
     +---- no VEX ----------> unassessed
```

This separation avoids treating a package-level vulnerability match as proof of runtime exploitability.

## Supported conversion paths

| From | To | Status |
|---|---|---|
| SPDX 2.3 | CycloneDX 1.7 | Supported subset mapping |
| CycloneDX 1.6+ | CycloneDX 1.7 | Up-conversion |
| CycloneDX | SPDX 3.0.1 | Supported subset mapping |
| SPDX 2.3 | SPDX 3.0.1 | Supported subset mapping |
| SPDX 2.3 | SPDX 3.1 | Experimental |
| CycloneDX | SPDX 3.1 | Experimental |

Conversions are intentionally loss-aware. Fields or relationship types that cannot be represented cleanly generate warnings. Use `--strict` to fail instead of accepting conversion warnings.

## Validation

Built-in validation is intentionally lightweight and offline. It checks document headers and core object shapes.

For compliance-grade validation, validate the generated document against the official target specification's JSON Schema/SHACL rules used by your environment.

## Example with a real SBOM

```bash
# Detect
sbom-convert grype.cdx.json --info

# Convert
sbom-convert grype.cdx.json \
  --to spdx-3.0.1 \
  --report conversion.json \
  -o grype.spdx.json

# Scan with OSV
sbom-convert grype.cdx.json \
  --osv-scan \
  --osv-report osv.json

# OSV + VEX correlation
sbom-convert grype.cdx.json \
  --osv-scan \
  --analyze-vex \
  --security-report security.json
```

For OSV batch queries, the official API guarantees response ordering matches the input query ordering and supports per-query pagination tokens.

## Docker

```bash
docker build -t sbom-converter .

docker run --rm \
  -v "$PWD:/data" \
  sbom-converter \
  /data/input.json \
  --to cdx-1.7 \
  -o /data/output.json
```

OSV is still opt-in inside Docker:

```bash
docker run --rm \
  -v "$PWD:/data" \
  sbom-converter \
  /data/input.json \
  --osv-scan \
  --osv-report /data/osv.json
```

## Security and privacy notes

- No network request is made during ordinary conversion.
- OSV requests are only made when `--osv-scan` or OSV-backed `--vex` is explicitly selected.
- Only component PURLs are sent to the fixed OSV HTTPS endpoint.
- The full SBOM file is not transmitted.
- OSV findings do not determine product exploitability.
- Gitleaks, Bandit, pip-audit, Semgrep, Trivy, Hadolint, Ruff and pytest run in CI.

## License

MIT. See `LICENSE`.
