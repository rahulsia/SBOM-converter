# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""OSV vulnerability discovery and VEX correlation.

OSV matching identifies known package/version vulnerabilities. It does not
decide product exploitability. Existing producer-supplied VEX is correlated
separately and retained as authoritative contextual assessment data.
"""
from __future__ import annotations

from collections import Counter

from .osv import query_osv_batch
from .vex import extract_products


def _embedded_cdx_vex(doc):
    result = {}
    if doc.get("bomFormat") != "CycloneDX":
        return result
    for vuln in doc.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict) or not vuln.get("id"):
            continue
        analysis = vuln.get("analysis") or {}
        affects = [
            x.get("ref")
            for x in vuln.get("affects", []) or []
            if isinstance(x, dict) and x.get("ref")
        ]
        result[vuln["id"]] = {
            "state": analysis.get("state"),
            "justification": analysis.get("justification"),
            "response": analysis.get("response", []),
            "detail": analysis.get("detail"),
            "affects": affects,
        }
    return result


def scan_osv(doc, timeout=15, batch_size=100):
    """Query OSV using PURLs and correlate matches with embedded VEX."""
    products = extract_products(doc)
    embedded = _embedded_cdx_vex(doc)

    findings_raw, skipped_names = query_osv_batch(
        products,
        timeout=timeout,
        batch_size=batch_size,
    )

    product_by_purl = {
        p.get("purl"): p
        for p in products
        if p.get("purl")
    }

    findings = []
    seen = set()
    for f in findings_raw:
        key = (f.vulnerability_id, f.purl)
        if key in seen:
            continue
        seen.add(key)
        product = product_by_purl.get(f.purl, {})
        vex = embedded.get(f.vulnerability_id)

        findings.append({
            "id": f.vulnerability_id,
            "component": f.component_name,
            "version": f.version,
            "purl": f.purl,
            "osvMatch": True,
            "exploitability": "not_determined_by_osv",
            "vex": vex,
            "vexStatus": vex.get("state") if vex else "no_vex_assertion",
            "modified": f.modified,
        })

    states = Counter(f["vexStatus"] for f in findings)
    return {
        "source": "OSV.dev",
        "endpoint": "https://api.osv.dev/v1/querybatch",
        "queryMode": "versioned_purl",
        "batchSize": batch_size,
        "componentsExamined": len(products),
        "componentsQueried": len({p.get("purl") for p in products if p.get("purl")}),
        "componentsSkippedNoPurl": len(skipped_names),
        "componentsSkipped": [
            {"name": name, "reason": "missing_purl"} for name in skipped_names
        ],
        "vulnerabilityMatches": len(findings),
        "vexCorrelation": dict(sorted(states.items())),
        "note": (
            "OSV matches identify known package/version vulnerabilities. "
            "They do not by themselves establish product exploitability."
        ),
        "findings": findings,
    }
