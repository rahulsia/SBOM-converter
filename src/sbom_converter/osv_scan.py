# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""OSV vulnerability discovery and VEX correlation.

This module discovers known vulnerabilities for SBOM components using OSV.dev.
An OSV match is NOT treated as proof that a vulnerability is exploitable in the
product. Existing producer-supplied VEX assertions are correlated separately.
"""
from __future__ import annotations

from collections import Counter

from .osv import query_osv
from .vex import extract_products


def _embedded_cdx_vex(doc):
    result = {}
    if doc.get("bomFormat") != "CycloneDX":
        return result
    for vuln in doc.get("vulnerabilities", []):
        vid = vuln.get("id")
        if not vid:
            continue
        analysis = vuln.get("analysis") or {}
        affects = [x.get("ref") for x in vuln.get("affects", []) if x.get("ref")]
        result[vid] = {
            "state": analysis.get("state"),
            "justification": analysis.get("justification"),
            "response": analysis.get("response", []),
            "detail": analysis.get("detail"),
            "affects": affects,
        }
    return result


def scan_osv(doc, timeout=15):
    """Query OSV for versioned PURLs and correlate results with embedded VEX.

    Returns a report only; this function never changes the source SBOM and never
    promotes an OSV package match to an exploitability assertion.
    """
    products = extract_products(doc)
    embedded = _embedded_cdx_vex(doc)
    findings = []
    skipped = []
    seen = set()

    for product in products:
        purl = product.get("purl")
        if not purl:
            skipped.append({"name": product.get("name"), "reason": "missing_purl"})
            continue
        # Prefer a versioned PURL. OSV accepts a version embedded in the PURL and
        # requires that a separate version field is not supplied in that case.
        if "@" not in purl and product.get("version") not in (None, "", "unknown"):
            skipped.append({"name": product.get("name"), "purl": purl, "reason": "unversioned_purl"})
            continue
        vulns = query_osv(purl, timeout=timeout)
        for vuln in vulns:
            vid = vuln.get("id")
            if not vid:
                continue
            key = (vid, purl)
            if key in seen:
                continue
            seen.add(key)
            vex = embedded.get(vid)
            aliases = vuln.get("aliases", []) if isinstance(vuln.get("aliases"), list) else []
            findings.append({
                "id": vid,
                "aliases": aliases,
                "component": product.get("name"),
                "version": product.get("version"),
                "purl": purl,
                "osvMatch": True,
                "exploitability": "not_determined_by_osv",
                "vex": vex,
                "vexStatus": vex.get("state") if vex else "no_vex_assertion",
                "summary": vuln.get("summary"),
                "modified": vuln.get("modified"),
            })

    states = Counter(f["vexStatus"] for f in findings)
    return {
        "source": "OSV.dev",
        "componentsExamined": len(products),
        "componentsQueried": len(products) - len(skipped),
        "componentsSkipped": skipped,
        "vulnerabilityMatches": len(findings),
        "vexCorrelation": dict(sorted(states.items())),
        "note": "OSV matches identify known package/version vulnerabilities; they do not by themselves establish product exploitability.",
        "findings": findings,
    }
