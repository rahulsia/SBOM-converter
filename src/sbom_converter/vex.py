# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""OpenVEX statement generation and validation.

Implements the OpenVEX specification (https://github.com/openvex/spec) for
documenting vulnerability exploitability against components found in an SBOM.
Fully offline and dependency-free: the vulnerability status/justification for
each entry must be supplied by the caller (a human or a local scanner), since
that information cannot be derived from SBOM structure alone.
"""
from __future__ import annotations

import uuid

from .core import AUTHOR, TOOL, VERSION, ValidationError, now

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


class VexError(ValidationError):
    pass


def extract_products(doc):
    entries = []
    if doc.get("bomFormat") == "CycloneDX":
        for c in doc.get("components", []):
            name = c.get("name")
            if not name:
                continue
            entries.append({"name": name, "version": c.get("version", "unknown"), "purl": c.get("purl")})
    elif "packages" in doc and "spdxVersion" in doc:
        for pkg in doc.get("packages", []):
            name = pkg.get("name")
            if not name:
                continue
            purl = None
            for er in pkg.get("externalRefs", []):
                if er.get("referenceType") == "purl":
                    purl = er.get("referenceLocator")
            entries.append({"name": name, "version": pkg.get("versionInfo", "unknown"), "purl": purl})
    elif "@graph" in doc:
        for item in doc.get("@graph", []):
            if item.get("type") not in ("software_Package", "Package"):
                continue
            name = item.get("name")
            if not name:
                continue
            purl = None
            for ei in item.get("externalIdentifier", []):
                if ei.get("externalIdentifierType") == "packageUrl":
                    purl = ei.get("identifier")
            entries.append({"name": name, "version": item.get("software_packageVersion", "unknown"), "purl": purl})
    return entries


def _product_id(entry):
    return entry["purl"] or f"{entry['name']}@{entry['version']}"


def _to_openvex_product(entry):
    product = {"@id": _product_id(entry)}
    if entry.get("purl"):
        product["identifiers"] = {"purl": entry["purl"]}
    return product


def validate_vex_input(data):
    if not isinstance(data, list):
        raise VexError("VEX input must be a JSON array of vulnerability statements.")
    if not data:
        raise VexError("VEX input must contain at least one vulnerability statement.")
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise VexError(f"VEX input[{i}] must be an object.")
        if not item.get("id"):
            raise VexError(f"VEX input[{i}] missing required 'id' (vulnerability identifier, e.g. CVE-2024-12345).")
        status = item.get("status")
        if status not in VALID_STATUSES:
            raise VexError(f"VEX input[{i}] has invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}")
        if status == "not_affected" and not item.get("justification") and not item.get("impact_statement"):
            raise VexError(f"VEX input[{i}] with status 'not_affected' requires 'justification' or 'impact_statement'.")
        if status == "not_affected" and item.get("justification") and item["justification"] not in VALID_JUSTIFICATIONS:
            raise VexError(f"VEX input[{i}] has invalid justification '{item['justification']}'. Must be one of: {', '.join(sorted(VALID_JUSTIFICATIONS))}")
        if status == "affected" and not item.get("action_statement"):
            raise VexError(f"VEX input[{i}] with status 'affected' requires 'action_statement'.")
        if "products" in item and not isinstance(item["products"], list):
            raise VexError(f"VEX input[{i}] 'products' must be a list of component names.")
    return data


def build_vex(sbom_doc, vulnerabilities, author=None, doc_id=None):
    entries = extract_products(sbom_doc)
    if not entries:
        raise VexError("No identifiable components/packages found in the SBOM to reference in VEX statements.")

    index = {}
    for e in entries:
        index.setdefault(e["name"], []).append(e)
        index.setdefault(_product_id(e), []).append(e)

    statements = []
    for v in vulnerabilities:
        targets = v.get("products")
        if targets:
            matched = []
            for t in targets:
                found = index.get(t)
                if not found:
                    raise VexError(f"VEX statement for '{v['id']}' references unknown product '{t}'.")
                matched.extend(found)
        else:
            matched = entries
        seen = set()
        product_objs = []
        for e in matched:
            pid = _product_id(e)
            if pid not in seen:
                seen.add(pid)
                product_objs.append(_to_openvex_product(e))
        stmt = {
            "vulnerability": {"name": v["id"]},
            "timestamp": v.get("timestamp", now()),
            "products": product_objs,
            "status": v["status"],
        }
        if v["status"] == "not_affected":
            if v.get("justification"):
                stmt["justification"] = v["justification"]
            if v.get("impact_statement"):
                stmt["impact_statement"] = v["impact_statement"]
        if v["status"] == "affected":
            stmt["action_statement"] = v["action_statement"]
        if v.get("status_notes"):
            stmt["status_notes"] = v["status_notes"]
        statements.append(stmt)

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id or f"urn:sbom-convert:vex:{uuid.uuid4()}",
        "author": author or f"{AUTHOR} ({TOOL} {VERSION})",
        "timestamp": now(),
        "version": 1,
        "statements": statements,
    }


def validate_vex(doc):
    if not isinstance(doc, dict):
        raise VexError(f"VEX document must be a JSON object, got {type(doc).__name__}")
    if doc.get("@context") != OPENVEX_CONTEXT:
        raise VexError(f"VEX '@context' must be '{OPENVEX_CONTEXT}', got {doc.get('@context')}")
    if not doc.get("@id"):
        raise VexError("VEX document missing required '@id'")
    if not doc.get("author"):
        raise VexError("VEX document missing required 'author'")
    if not doc.get("timestamp"):
        raise VexError("VEX document missing required 'timestamp'")
    if not isinstance(doc.get("version"), int):
        raise VexError("VEX document 'version' must be an integer")
    statements = doc.get("statements")
    if not isinstance(statements, list) or not statements:
        raise VexError("VEX document 'statements' must be a non-empty list")
    for i, s in enumerate(statements):
        if not isinstance(s, dict):
            raise VexError(f"statements[{i}] must be an object")
        if not s.get("vulnerability", {}).get("name"):
            raise VexError(f"statements[{i}] missing required 'vulnerability.name'")
        if not isinstance(s.get("products"), list) or not s["products"]:
            raise VexError(f"statements[{i}] must reference at least one product")
        for j, p in enumerate(s["products"]):
            if not isinstance(p, dict) or not p.get("@id"):
                raise VexError(f"statements[{i}].products[{j}] missing required '@id'")
        status = s.get("status")
        if status not in VALID_STATUSES:
            raise VexError(f"statements[{i}] has invalid status '{status}'")
        if status == "not_affected" and not (s.get("justification") or s.get("impact_statement")):
            raise VexError(f"statements[{i}] with status 'not_affected' requires 'justification' or 'impact_statement'")
        if status == "not_affected" and s.get("justification") and s["justification"] not in VALID_JUSTIFICATIONS:
            raise VexError(f"statements[{i}] has invalid justification '{s['justification']}'")
        if status == "affected" and not s.get("action_statement"):
            raise VexError(f"statements[{i}] with status 'affected' requires 'action_statement'")
    return True
