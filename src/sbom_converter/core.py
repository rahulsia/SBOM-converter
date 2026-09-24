# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from __future__ import annotations

import copy
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import __version__

AUTHOR = "Rahul Kumar"
EMAIL = "rahulk.3477@gmail.com"
TOOL = "sbom-convert"
VERSION = __version__


class SbomError(Exception):
    pass


class UnsupportedInput(SbomError):
    pass


class ValidationError(SbomError):
    pass


class ConversionError(SbomError):
    pass


@dataclass
class WarningItem:
    code: str
    message: str
    path: str = ""


@dataclass
class Report:
    input_format: str = ""
    target_format: str = ""
    warnings: list[WarningItem] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def warn(self, code, message, path=""):
        self.warnings.append(WarningItem(code, message, path))

    def json(self):
        return json.dumps(
            {
                "tool": f"{TOOL} {VERSION}",
                "author": AUTHOR,
                "email": EMAIL,
                "inputFormat": self.input_format,
                "targetFormat": self.target_format,
                "stats": self.stats,
                "warnings": [asdict(x) for x in self.warnings],
            },
            indent=2,
        )


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe(s):
    return (re.sub(r"[^A-Za-z0-9.-]+", "-", str(s or "item")).strip("-")[:80] or "item")


def stable_id(prefix, seed):
    return f"urn:sbom-convert:{prefix}:{safe(seed)}:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def detect(doc):
    if not isinstance(doc, dict):
        raise UnsupportedInput("Input must be a JSON object.")
    if doc.get("bomFormat") == "CycloneDX":
        return f"cyclonedx-{doc.get('specVersion', '')}"
    if str(doc.get("spdxVersion", "")).startswith("SPDX-2.3"):
        return "spdx-2.3"
    ctx = str(doc.get("@context", ""))
    if "spdx.org/rdf/3.0.1" in ctx:
        return "spdx-3.0.1"
    if "spdx.org/rdf/3.1" in ctx:
        return "spdx-3.1"
    raise UnsupportedInput("Could not identify SPDX or CycloneDX JSON input.")


def basic_validate(doc, fmt):
    if fmt.startswith("cyclonedx-"):
        if doc.get("bomFormat") != "CycloneDX" or not doc.get("specVersion"):
            raise ValidationError("Invalid CycloneDX document header.")
        if "components" in doc and not isinstance(doc["components"], list):
            raise ValidationError("CycloneDX 'components' must be a list.")
        if "dependencies" in doc and not isinstance(doc["dependencies"], list):
            raise ValidationError("CycloneDX 'dependencies' must be a list.")
    elif fmt == "spdx-2.3":
        for k in ("spdxVersion", "SPDXID", "name", "dataLicense", "documentNamespace", "creationInfo"):
            if k not in doc:
                raise ValidationError(f"SPDX 2.3 missing required field: {k}")
        if "packages" in doc and not isinstance(doc["packages"], list):
            raise ValidationError("SPDX 2.3 'packages' must be a list.")
        if "relationships" in doc and not isinstance(doc["relationships"], list):
            raise ValidationError("SPDX 2.3 'relationships' must be a list.")
    elif fmt.startswith("spdx-3"):
        if "@context" not in doc or not isinstance(doc.get("@graph"), list):
            raise ValidationError("SPDX 3 JSON-LD requires @context and @graph.")
    return True


def spdx2_to_cdx(doc, report):
    out = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now(),
            "authors": [{"name": AUTHOR, "email": EMAIL}],
            "tools": {"components": [{"type": "application", "name": TOOL, "version": VERSION, "author": AUTHOR}]},
        },
        "components": [],
    }
    ids = {}
    for i, p in enumerate(doc.get("packages", [])):
        ref = p.get("SPDXID") or f"pkg-{i}"
        ids[ref] = ref
        c = {"type": "library", "bom-ref": ref, "name": p.get("name", "unnamed")}
        if p.get("versionInfo"):
            c["version"] = p["versionInfo"]
        if p.get("supplier"):
            c["supplier"] = {"name": p["supplier"].split(":", 1)[-1].strip()}
        hs = []
        amap = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5"}
        for h in p.get("checksums", []):
            if h.get("algorithm") in amap and h.get("checksumValue"):
                hs.append({"alg": amap[h["algorithm"]], "content": h["checksumValue"]})
        if hs:
            c["hashes"] = hs
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        if lic and lic not in ("NOASSERTION", "NONE"):
            c["licenses"] = [{"expression": lic}]
        if p.get("copyrightText") not in (None, "NOASSERTION", "NONE"):
            c["copyright"] = [{"text": p["copyrightText"]}]
        for er in p.get("externalRefs", []):
            if er.get("referenceType") == "purl":
                c["purl"] = er.get("referenceLocator")
                break
        out["components"].append(c)
    deps = {}
    for r in doc.get("relationships", []):
        a, b, t = r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType", "")
        if a in ids and b in ids and t in ("DEPENDS_ON", "DYNAMIC_LINK", "STATIC_LINK"):
            deps.setdefault(a, set()).add(b)
        elif t not in ("DESCRIBES", "CONTAINS"):
            report.warn("RELATIONSHIP_NOT_MAPPED", f"SPDX relationship {t} not represented in CycloneDX dependency graph.")
    if deps:
        out["dependencies"] = [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())]
    if doc.get("files"):
        report.warn("FILES_NOT_MAPPED", "SPDX file-level objects are not emitted as CycloneDX components.")
    report.stats = {"components": len(out["components"]), "relationships": len(doc.get("relationships", []))}
    return out


def cdx_to_cdx17(doc, report):
    out = copy.deepcopy(doc)
    old = str(out.get("specVersion", ""))
    out["bomFormat"] = "CycloneDX"
    out["specVersion"] = "1.7"
    out.setdefault("version", 1)
    out.setdefault("serialNumber", f"urn:uuid:{uuid.uuid4()}")
    md = out.setdefault("metadata", {})
    md.setdefault("timestamp", now())
    props = md.setdefault("properties", [])
    props.extend(
        [
            {"name": "sbom-convert:converted-from", "value": f"CycloneDX {old}"},
            {"name": "sbom-convert:converter", "value": f"{TOOL} {VERSION}"},
        ]
    )
    if old != "1.7":
        report.warn("UPCONVERT", "Existing fields were retained; new 1.7-only information cannot be inferred from an older BOM.")
    report.stats = {"components": len(out.get("components", [])), "dependencies": len(out.get("dependencies", []))}
    return out


def spdx2_to_spdx3(doc, report, target="3.0.1"):
    context = (
        "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        if target == "3.0.1"
        else "https://spdx.org/rdf/3.1/spdx-context.jsonld"
    )
    ci = "_:creationinfo"
    person = stable_id("person", EMAIL)
    ns = doc.get("documentNamespace", doc.get("name", "document"))
    docid = stable_id("document", ns)
    sbomid = stable_id("sbom", ns)
    graph = [
        {"type": "CreationInfo", "@id": ci, "specVersion": target, "createdBy": [person], "created": now()},
        {
            "type": "Person",
            "spdxId": person,
            "creationInfo": ci,
            "name": AUTHOR,
            "externalIdentifier": [{"type": "ExternalIdentifier", "externalIdentifierType": "email", "identifier": EMAIL}],
        },
    ]
    pkg_ids = []
    oldnew = {}
    rel_ids = []
    for i, p in enumerate(doc.get("packages", [])):
        old = p.get("SPDXID") or f"pkg-{i}"
        pid = stable_id("package", ns + ":" + old)
        oldnew[old] = pid
        pkg_ids.append(pid)
        x = {"type": "software_Package", "spdxId": pid, "creationInfo": ci, "name": p.get("name", "unnamed")}
        if p.get("versionInfo"):
            x["software_packageVersion"] = p["versionInfo"]
        eis = []
        for er in p.get("externalRefs", []):
            if er.get("referenceType") == "purl" and er.get("referenceLocator"):
                eis.append({"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl", "identifier": er["referenceLocator"]})
        if eis:
            x["externalIdentifier"] = eis
        graph.append(x)
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        if lic and lic not in ("NOASSERTION", "NONE"):
            lid = stable_id("license", lic)
            graph.append({"type": "simplelicensing_LicenseExpression", "spdxId": lid, "creationInfo": ci, "licenseExpression": lic})
            rid = stable_id("rel", pid + ":license:" + lic)
            rel_ids.append(rid)
            graph.append({"type": "Relationship", "spdxId": rid, "creationInfo": ci, "from": pid, "to": [lid], "relationshipType": "hasConcludedLicense"})
        if p.get("copyrightText") not in (None, "NOASSERTION", "NONE"):
            report.warn("COPYRIGHT_PRESERVATION", "Package copyright requires consumer-specific SPDX 3 licensing-profile verification.", old)
    rmap = {"DEPENDS_ON": "dependsOn", "CONTAINS": "contains", "DESCRIBES": "describes", "DYNAMIC_LINK": "hasDynamicLink", "STATIC_LINK": "hasStaticLink"}
    for r in doc.get("relationships", []):
        a, b = oldnew.get(r.get("spdxElementId")), oldnew.get(r.get("relatedSpdxElement"))
        typ = rmap.get(r.get("relationshipType"))
        if a and b and typ:
            rid = stable_id("rel", a + ":" + typ + ":" + b)
            rel_ids.append(rid)
            graph.append({"type": "Relationship", "spdxId": rid, "creationInfo": ci, "from": a, "to": [b], "relationshipType": typ})
        elif r.get("relationshipType") not in ("DESCRIBES",):
            report.warn("RELATIONSHIP_NOT_MAPPED", f"Relationship {r.get('relationshipType')} was not mapped.")
    graph.extend(
        [
            {
                "type": "SpdxDocument",
                "spdxId": docid,
                "creationInfo": ci,
                "profileConformance": ["core", "software", "simpleLicensing"],
                "rootElement": [sbomid],
                "element": [sbomid, *pkg_ids, *rel_ids],
            },
            {
                "type": "software_Sbom",
                "spdxId": sbomid,
                "creationInfo": ci,
                "profileConformance": ["core", "software", "simpleLicensing"],
                "rootElement": pkg_ids[:1] or [],
            },
        ]
    )
    if target == "3.1":
        report.warn("EXPERIMENTAL_TARGET", "SPDX 3.1 output is experimental and MUST be validated against the exact 3.1 schema/model adopted by your environment.")
    report.stats = {"packages": len(pkg_ids), "relationships": len(rel_ids)}
    return {"@context": context, "@graph": graph}


def cdx_to_spdx3(doc, report, target="3.0.1"):
    tmp = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "CycloneDX import",
        "dataLicense": "CC0-1.0",
        "documentNamespace": doc.get("serialNumber", f"urn:uuid:{uuid.uuid4()}"),
        "creationInfo": {"created": doc.get("metadata", {}).get("timestamp", now()), "creators": ["Tool: sbom-convert"]},
        "packages": [],
        "relationships": [],
    }
    for i, c in enumerate(doc.get("components", [])):
        ref = c.get("bom-ref") or f"SPDXRef-{safe(c.get('name', 'component'))}-{i}"
        p = {"SPDXID": ref, "name": c.get("name", "unnamed")}
        if c.get("version"):
            p["versionInfo"] = c["version"]
        if c.get("purl"):
            p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c["purl"]}]
        if c.get("licenses"):
            l = c["licenses"][0]
            p["licenseConcluded"] = l.get("expression") or l.get("license", {}).get("id") or "NOASSERTION"
        tmp["packages"].append(p)
    for d in doc.get("dependencies", []):
        for b in d.get("dependsOn", []):
            tmp["relationships"].append({"spdxElementId": d.get("ref"), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": b})
    return spdx2_to_spdx3(tmp, report, target)


def convert(doc, target, strict=False):
    src = detect(doc)
    basic_validate(doc, src)
    report = Report(src, target)
    if target == "cdx-1.7":
        if src.startswith("cyclonedx-"):
            out = cdx_to_cdx17(doc, report)
        elif src == "spdx-2.3":
            out = spdx2_to_cdx(doc, report)
        else:
            raise ConversionError(f"{src} -> {target} is not implemented.")
    elif target in ("spdx-3.0.1", "spdx-3.1"):
        ver = target.split("-", 1)[1]
        if src == "spdx-2.3":
            out = spdx2_to_spdx3(doc, report, ver)
        elif src.startswith("cyclonedx-"):
            out = cdx_to_spdx3(doc, report, ver)
        else:
            raise ConversionError(f"{src} -> {target} is not implemented.")
    else:
        raise ConversionError(f"Unsupported target: {target}")
    if strict and report.warnings:
        raise ConversionError("Strict mode rejected a conversion with warnings: " + report.warnings[0].message)
    return out, report
