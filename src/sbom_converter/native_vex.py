# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""CycloneDX VEX analysis and SPDX 3.0.1 Security-profile mapping."""
from __future__ import annotations

from collections import Counter

from .core import ValidationError, stable_id

STATE_TO_SPDX = {
    "exploitable": ("VexAffectedVulnAssessmentRelationship", "affects"),
    "not_affected": ("VexNotAffectedVulnAssessmentRelationship", "doesNotAffect"),
    "resolved": ("VexFixedVulnAssessmentRelationship", "fixedIn"),
    "resolved_with_pedigree": ("VexFixedVulnAssessmentRelationship", "fixedIn"),
}
JUSTIFICATION_TO_SPDX = {
    "code_not_present": "vulnerableCodeNotPresent",
    "code_not_reachable": "vulnerableCodeNotInExecutePath",
    "requires_configuration": "vulnerableCodeCannotBeControlledByAdversary",
    "requires_dependency": "vulnerableCodeNotInExecutePath",
    "requires_environment": "vulnerableCodeCannotBeControlledByAdversary",
    "protected_by_compiler": "inlineMitigationsAlreadyExist",
    "protected_at_runtime": "inlineMitigationsAlreadyExist",
    "protected_at_perimeter": "inlineMitigationsAlreadyExist",
    "protected_by_mitigating_control": "inlineMitigationsAlreadyExist",
}


def analyze_cyclonedx_vex(doc):
    """Summarize embedded CycloneDX vulnerability/VEX assertions without inventing status."""
    vulns = doc.get("vulnerabilities", [])
    if vulns is None:
        vulns = []
    if not isinstance(vulns, list):
        raise ValidationError("CycloneDX 'vulnerabilities' must be a list")
    states, justifications, responses = Counter(), Counter(), Counter()
    warnings = []
    affected_refs = set()
    for i, vuln in enumerate(vulns):
        if not isinstance(vuln, dict):
            warnings.append({"code": "INVALID_VULNERABILITY", "path": f"vulnerabilities[{i}]"})
            continue
        analysis = vuln.get("analysis") or {}
        state = analysis.get("state", "unassessed")
        states[state] += 1
        if analysis.get("justification"):
            justifications[analysis["justification"]] += 1
        for response in analysis.get("response", []) or []:
            responses[response] += 1
        if state == "not_affected" and not (analysis.get("justification") or analysis.get("detail")):
            warnings.append({"code": "NOT_AFFECTED_WITHOUT_RATIONALE", "path": f"vulnerabilities[{i}].analysis"})
        if state == "exploitable" and not (analysis.get("response") or analysis.get("detail")):
            warnings.append({"code": "EXPLOITABLE_WITHOUT_RESPONSE", "path": f"vulnerabilities[{i}].analysis"})
        for affect in vuln.get("affects", []) or []:
            if isinstance(affect, dict) and affect.get("ref"):
                affected_refs.add(affect["ref"])
    return {
        "totalVulnerabilities": len(vulns),
        "states": dict(sorted(states.items())),
        "justifications": dict(sorted(justifications.items())),
        "responses": dict(sorted(responses.items())),
        "affectedComponentRefs": sorted(affected_refs),
        "warnings": warnings,
    }


def _spdx_packages_by_cdx_ref(cdx_doc, spdx_doc):
    packages = [x for x in spdx_doc.get("@graph", []) if x.get("type") == "software_Package"]
    by_purl = {}
    for p in packages:
        for ext in p.get("externalIdentifier", []) or []:
            if ext.get("externalIdentifierType") == "packageUrl" and ext.get("identifier"):
                by_purl[ext["identifier"]] = p.get("spdxId")
    result = {}
    for c in cdx_doc.get("components", []) or []:
        ref, purl = c.get("bom-ref"), c.get("purl")
        if ref and purl and purl in by_purl:
            result[ref] = by_purl[purl]
    return result


def augment_spdx3_with_cdx_vex(cdx_doc, spdx_doc, report=None):
    """Add SPDX 3 Security-profile Vulnerability and VEX assessment elements.

    Unsupported/ambiguous CycloneDX states are reported, never guessed.
    """
    graph = spdx_doc.setdefault("@graph", [])
    refmap = _spdx_packages_by_cdx_ref(cdx_doc, spdx_doc)
    added = []
    for i, vuln in enumerate(cdx_doc.get("vulnerabilities", []) or []):
        vid = vuln.get("id")
        if not vid:
            if report:
                report.warn("VEX_MISSING_ID", "CycloneDX vulnerability has no id", f"vulnerabilities[{i}]")
            continue
        vuln_id = stable_id("vulnerability", vid)
        if not any(x.get("spdxId") == vuln_id for x in graph):
            node = {
                "type": "security_Vulnerability",
                "spdxId": vuln_id,
                "creationInfo": "_:creationinfo",
                "name": vid,
                "externalIdentifier": [{"type": "ExternalIdentifier", "externalIdentifierType": "cve", "identifier": vid}]
                if vid.upper().startswith("CVE-") else [],
            }
            graph.append(node); added.append(vuln_id)
        analysis = vuln.get("analysis") or {}
        state = analysis.get("state")
        mapping = STATE_TO_SPDX.get(state)
        targets = []
        for affect in vuln.get("affects", []) or []:
            if isinstance(affect, dict) and affect.get("ref") in refmap:
                targets.append(refmap[affect["ref"]])
            elif report and isinstance(affect, dict) and affect.get("ref"):
                report.warn("VEX_TARGET_NOT_MAPPED", f"Could not map CycloneDX bom-ref {affect['ref']} to SPDX package", f"vulnerabilities[{i}].affects")
        if not mapping or not targets:
            if report and state in ("in_triage", "false_positive"):
                report.warn("VEX_STATE_NOT_DIRECTLY_MAPPABLE", f"CycloneDX VEX state '{state}' has no direct SPDX VEX relationship; assertion retained in report", f"vulnerabilities[{i}].analysis.state")
            continue
        cls, reltype = mapping
        rel = {
            "type": f"security_{cls}",
            "spdxId": stable_id("vex", f"{vid}:{state}:{','.join(sorted(targets))}"),
            "creationInfo": "_:creationinfo",
            "from": vuln_id,
            "to": sorted(set(targets)),
            "relationshipType": reltype,
        }
        detail = analysis.get("detail")
        if state == "not_affected":
            justification = analysis.get("justification")
            if justification in JUSTIFICATION_TO_SPDX:
                rel["security_justificationType"] = JUSTIFICATION_TO_SPDX[justification]
            if detail:
                rel["security_impactStatement"] = detail
            if not (justification or detail) and report:
                report.warn("VEX_NOT_AFFECTED_INCOMPLETE", "not_affected requires a justification or impact detail for a useful VEX assertion", f"vulnerabilities[{i}].analysis")
        elif state == "exploitable":
            responses = analysis.get("response") or []
            rel["security_actionStatement"] = detail or ("Response: " + ", ".join(responses) if responses else "Affected; remediation action not supplied")
        elif detail:
            rel["security_statusNotes"] = detail
        graph.append(rel); added.append(rel["spdxId"])
    # advertise Security profile on document/SBOM elements
    if added:
        for item in graph:
            if item.get("type") in ("SpdxDocument", "software_Sbom"):
                profiles = item.setdefault("profileConformance", [])
                if "security" not in profiles:
                    profiles.append("security")
                if item.get("type") == "SpdxDocument":
                    elements = item.setdefault("element", [])
                    for element in added:
                        if element not in elements:
                            elements.append(element)
    return spdx_doc
