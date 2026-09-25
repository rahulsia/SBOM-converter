# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""Optional OSV.dev vulnerability lookup and enrichment.

Network access is opt-in. Normal SBOM conversion never contacts OSV.
When enabled, only versioned package URLs (PURLs) are sent to OSV.dev.
The implementation uses the official /v1/querybatch endpoint and follows
per-query pagination tokens.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from . import __version__
from .core import SbomError

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT = 15
DEFAULT_BATCH_SIZE = 100
USER_AGENT = f"sbom-convert/{__version__}"


class OsvError(SbomError):
    pass


@dataclass(frozen=True)
class OsvFinding:
    component_name: str
    version: str
    purl: str
    vulnerability_id: str
    modified: str | None = None

    def as_dict(self):
        return {
            "component": self.component_name,
            "version": self.version,
            "purl": self.purl,
            "vulnerability": self.vulnerability_id,
            "modified": self.modified,
            "exploitability": "not_determined_by_osv",
        }


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise OsvError(f"OSV.dev returned HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise OsvError(f"OSV.dev lookup failed: {e}") from e
    except json.JSONDecodeError as e:
        raise OsvError(f"OSV.dev returned invalid JSON: {e}") from e
    if not isinstance(body, dict):
        raise OsvError("OSV.dev returned an unexpected response.")
    return body


def query_osv_batch(
    entries: list[dict],
    timeout: int = DEFAULT_TIMEOUT,
    batch_size: int = DEFAULT_BATCH_SIZE,
    on_batch: Callable[[int, int], None] | None = None,
) -> tuple[list[OsvFinding], list[str]]:
    """Query unique versioned PURLs in batches and handle pagination."""
    batch_size = max(1, batch_size)
    valid: list[dict] = []
    skipped: list[str] = []
    seen_purls: set[str] = set()

    for entry in entries:
        purl = entry.get("purl")
        if not purl:
            skipped.append(entry.get("name", "unknown"))
            continue
        if purl in seen_purls:
            continue
        seen_purls.add(purl)
        valid.append(entry)

    findings: list[OsvFinding] = []

    for start in range(0, len(valid), batch_size):
        batch = valid[start : start + batch_size]
        if on_batch:
            on_batch(start + 1, start + len(batch))

        tokens: list[str | None] = [None] * len(batch)
        while True:
            queries = []
            for entry, token in zip(batch, tokens):
                q = {"package": {"purl": entry["purl"]}}
                if token:
                    q["page_token"] = token
                queries.append(q)

            response = _post_json(OSV_QUERYBATCH_URL, {"queries": queries}, timeout)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(batch):
                raise OsvError("OSV querybatch response did not contain one result per query.")

            next_tokens: list[str | None] = [None] * len(batch)
            for idx, (entry, result) in enumerate(zip(batch, results)):
                if not isinstance(result, dict):
                    raise OsvError(f"Invalid OSV result for {entry['purl']}.")
                for vuln in result.get("vulns", []) or []:
                    if not isinstance(vuln, dict) or not vuln.get("id"):
                        continue
                    findings.append(
                        OsvFinding(
                            component_name=entry.get("name", "unknown"),
                            version=entry.get("version", "unknown"),
                            purl=entry["purl"],
                            vulnerability_id=vuln["id"],
                            modified=vuln.get("modified"),
                        )
                    )
                next_tokens[idx] = result.get("next_page_token")

            if not any(next_tokens):
                break
            tokens = next_tokens

    return findings, skipped


def lookup_vulnerabilities(entries, timeout=DEFAULT_TIMEOUT, on_query=None, batch_size=DEFAULT_BATCH_SIZE):
    findings, skipped = query_osv_batch(
        entries,
        timeout=timeout,
        batch_size=batch_size,
        on_batch=(lambda first, last: on_query(entries[first - 1]) if on_query else None),
    )
    statements = []
    seen = set()
    for finding in findings:
        key = (finding.vulnerability_id, finding.component_name, finding.purl)
        if key in seen:
            continue
        seen.add(key)
        statements.append(
            {
                "id": finding.vulnerability_id,
                "status": "under_investigation",
                "status_notes": (
                    f"Detected by OSV.dev for {finding.purl}; "
                    "exploitability has not been determined by OSV."
                ),
                "products": [finding.component_name],
            }
        )
    return statements, skipped


def osv_report(entries, findings, skipped, batch_size=DEFAULT_BATCH_SIZE):
    return {
        "tool": f"sbom-convert {__version__}",
        "source": "OSV.dev",
        "endpoint": OSV_QUERYBATCH_URL,
        "queryMode": "PURL",
        "batchSize": batch_size,
        "componentsQueried": len({e.get("purl") for e in entries if e.get("purl")}),
        "componentsSkippedNoPurl": len(skipped),
        "findings": [f.as_dict() for f in findings],
        "warnings": [
            {"code": "NO_PURL", "message": f"No PURL available for component: {name}"}
            for name in skipped
        ],
    }
