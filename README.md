# SBOM Converter

Copyright (c) 2026 Rahul Kumar  
Author: Rahul Kumar — rahulk.3477@gmail.com  
License: MIT (`SPDX-License-Identifier: MIT`)

CLI and Docker utility for pragmatic JSON SBOM conversion.

## Supported conversion paths

- SPDX 2.3 JSON → SPDX 3.0.1 JSON-LD
- SPDX 2.3 JSON → SPDX 3.1 JSON-LD (experimental)
- SPDX 2.3 JSON → CycloneDX 1.7 JSON
- CycloneDX JSON (including 1.6) → CycloneDX 1.7 JSON
- CycloneDX JSON (including 1.6) → SPDX 3.0.1 JSON-LD
- CycloneDX JSON (including 1.6) → SPDX 3.1 JSON-LD (experimental)

## Local CLI

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .

sbom-convert input.json --info
sbom-convert input.json --validate
sbom-convert input.json --to spdx-3.0.1 -o output.json --report report.json
sbom-convert input.json --to cdx-1.7 -o output.json --report report.json
```

## Docker

```bash
docker build -t sbom-converter .
docker run --rm -v "$PWD:/data" sbom-converter /data/input.json --to cdx-1.7 -o /data/output.json --report /data/report.json
```

Use `--strict` to reject conversions that produce mapping warnings. Built-in validation is intentionally lightweight and offline-friendly; for compliance use the official target-standard validator/schema.

SPDX 3.1 output is experimental and must be validated against the exact SPDX 3.1 model/schema adopted by your environment.

## License

MIT. See `LICENSE`.
