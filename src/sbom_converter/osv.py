# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""Optional OSV.dev lookup to auto-populate VEX vulnerability data.

OSV (https://osv.dev) is Google's open, free vulnerability database for
open source packages. This module is only invoked when the caller
explicitly asks for it (`--vex` without `--vex-input`). Only a single
component's package URL (purl) is sent per request -- never the full SBOM
document, and no other file content leaves the machine.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__
from .core import SbomError

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 15
USER_AGENT = f"sbom-convert/{__version__}"


class OsvError(SbomError):
    pass


def query_osv(purl, timeout=DEFAULT_TIMEOUT):
    payload = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise OsvError(f"OSV.dev lookup failed for {purl}: {e}")
    except json.JSONDecodeError as e:
        raise OsvError(f"OSV.dev returned invalid JSON for {purl}: {e}")
    if not isinstance(body, dict):
        raise OsvError(f"OSV.dev returned an unexpected response for {purl}")
    return body.get("vulns", [])


def lookup_vulnerabilities(entries, timeout=DEFAULT_TIMEOUT, on_query=None):
    statements = []
    skipped = []
    seen = set()
    for entry in entries:
        purl = entry.get("purl")
        if not purl:
            skipped.append(entry["name"])
            continue
        if on_query:
            on_query(entry)
        for v in query_osv(purl, timeout=timeout):
            vid = v.get("id")
            if not vid or (vid, entry["name"]) in seen:
                continue
            seen.add((vid, entry["name"]))
            summary = v.get("summary") or (v.get("details") or "")[:200]
            note = f"Detected via OSV.dev against {purl}."
            if summary:
                note += f" {summary}"
            statements.append(
                {
                    "id": vid,
                    "status": "under_investigation",
                    "status_notes": note,
                    "products": [entry["name"]],
                }
            )
    return statements, skipped
