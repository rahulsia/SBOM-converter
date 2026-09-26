# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT

# SBOM Converter API Reference

## Overview

The REST API is an optional interface over the same service layer used by the CLI.

Install:

```bash
python -m pip install "sbom-converter-rahul[api]"
```

Start:

```bash
sbom-api
```

Default bind address:

```text
0.0.0.0:8000
```

The API is intentionally stateless. An SBOM is supplied in each request.

## Content type

All POST endpoints accept:

```http
Content-Type: application/json
```

The SBOM must be supplied as a parsed JSON object under the `sbom` field.

## GET /health

Health/version endpoint.

### Request

No body.

### Response

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

## POST /convert

Converts an SPDX or CycloneDX JSON SBOM.

### Required parameters

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `sbom` | object | yes | SPDX 2.3 / SPDX 3.x / CycloneDX SBOM JSON |
| `target` | string | yes | `cdx-1.7`, `spdx-3.0.1`, or `spdx-3.1` |

### Optional parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `strict` | boolean | false | Treat conversion warnings as errors |

### Example

```bash
curl -X POST http://localhost:8000/convert \
  -H 'Content-Type: application/json' \
  -d '{
    "sbom": <SBOM_JSON>,
    "target": "cdx-1.7",
    "strict": false
  }'
```

### Response

```json
{
  "inputFormat": "spdx-2.3",
  "targetFormat": "cdx-1.7",
  "sbom": {},
  "report": {
    "inputFormat": "spdx-2.3",
    "targetFormat": "cdx-1.7",
    "stats": {},
    "warnings": []
  }
}
```

Conversion is offline. This endpoint does not call OSV or NVD.

## POST /scan

Runs vulnerability intelligence providers against the supplied SBOM.

### Required parameters

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `sbom` | object | yes | SBOM JSON |

### Optional parameters

| Parameter | Type | Default | Description |
|---|---|---:|---|
| `sources` | array | [`osv`, `nvd`] | `osv`, `nvd`, or both |
| `osvBatchSize` | integer | 100 | Number of PURLs sent per OSV `/v1/querybatch` request |
| `osvTimeout` | integer | 15 | OSV HTTPS timeout in seconds |
| `nvdTimeout` | integer | 20 | NVD HTTPS timeout in seconds |
| `nvdApiKey` | string/null | null | Optional NVD API key |
| `nvdDelay` | number/null | provider default | Minimum delay between NVD requests |

### Source behavior

```text
sources = ["osv"]
    PURL -> OSV.dev

sources = ["nvd"]
    CPE -> NVD/NIST

sources = ["osv", "nvd"]
    PURL -> OSV.dev
    CPE  -> NVD/NIST
```

OSV uses versioned PURLs. NVD uses CPE identifiers present in the SBOM.

### Example: both providers

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "sbom": <SBOM_JSON>,
    "sources": ["osv", "nvd"],
    "osvBatchSize": 100,
    "osvTimeout": 15,
    "nvdTimeout": 20
  }'
```

### NVD API key

Prefer deployment configuration or a secrets manager. The API accepts:

```json
{
  "nvdApiKey": "<NVD_API_KEY>"
}
```

Do not commit an API key to source control.

### Response

The response contains provider-specific results plus normalized findings:

```json
{
  "inputFormat": "spdx-2.3",
  "sources": {
    "osv": {},
    "nvd": {}
  },
  "findings": [
    {
      "source": "NVD/NIST",
      "id": "CVE-YYYY-NNNN",
      "component": "example",
      "version": "1.2.3",
      "cpe": "cpe:2.3:...",
      "exploitability": "not_determined_by_nvd"
    }
  ]
}
```

## POST /vex/analyze

Analyzes embedded CycloneDX vulnerability/VEX assertions.

### Required parameters

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `sbom` | object | yes | CycloneDX SBOM containing optional `vulnerabilities` |

This endpoint is offline and does not call OSV or NVD.

### Example

```bash
curl -X POST http://localhost:8000/vex/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sbom": <CYCLONEDX_SBOM_JSON>}'
```

### Response

The analysis contains:

```text
totalVulnerabilities
states
justifications
responses
affectedComponentRefs
warnings
```

## VEX semantics

OSV/NVD findings are vulnerability intelligence. They are not themselves VEX assertions.

The converter follows this model:

```text
Known vulnerability
       |
       v
Does an existing contextual VEX assertion exist?
       |
   +---+---+
   |       |
  yes      no
   |       |
 preserve  unassessed
 status
```

When automatically generating OpenVEX from provider findings, the default status is
`under_investigation` unless a supplied contextual assertion is used.

## Error handling

Malformed requests return HTTP 400 with a JSON `detail` message.

Typical causes:

```text
Missing sbom
Missing target
Unsupported target
Invalid SBOM structure
No CPE available for an NVD-only scan
No identifiable package/PURL for an OSV-only scan
```

## Python API equivalent

Everything exposed by the REST adapter is backed by the public Python API:

```python
from sbom_converter import (
    convert_sbom,
    scan_vulnerabilities,
    analyze_vex,
)

converted = convert_sbom(sbom, "cdx-1.7")
security = scan_vulnerabilities(sbom, sources=["osv", "nvd"])
vex = analyze_vex(sbom)
```

This means applications can integrate the converter without running an HTTP server.
