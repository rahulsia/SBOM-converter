# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
"""NVD/NIST CVE 2.0 vulnerability lookup using SBOM CPE identifiers."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from . import __version__
from .core import SbomError

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 20
DEFAULT_RESULTS_PER_PAGE = 2000
DEFAULT_DELAY_WITHOUT_KEY = 6.1
DEFAULT_DELAY_WITH_KEY = 0.7
MAX_RETRIES = 3
USER_AGENT = f"sbom-convert/{__version__}"


class NvdError(SbomError):
    pass


@dataclass(frozen=True)
class NvdFinding:
    component_name: str
    version: str
    cpe: str
    vulnerability_id: str
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    cvss_version: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None

    def as_dict(self):
        return {
            "component": self.component_name,
            "version": self.version,
            "cpe": self.cpe,
            "vulnerability": self.vulnerability_id,
            "published": self.published,
            "lastModified": self.last_modified,
            "description": self.description,
            "cvss": {
                "version": self.cvss_version,
                "baseScore": self.cvss_base_score,
                "severity": self.cvss_severity,
            },
            "exploitability": "not_determined_by_nvd",
        }


def _post_json(url: str, headers: dict[str, str], timeout: int) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                body = json.loads(resp.read().decode("utf-8"))
            if not isinstance(body, dict):
                raise NvdError("NVD returned an unexpected response.")
            return body
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < MAX_RETRIES:
                retry_after = e.headers.get("Retry-After")
                try:
                    delay = max(1.0, float(retry_after)) if retry_after else 2 ** attempt
                except ValueError:
                    delay = 2 ** attempt
                time.sleep(delay)
                continue
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise NvdError(f"NVD returned HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise NvdError(f"NVD lookup failed: {e}") from e
        except json.JSONDecodeError as e:
            raise NvdError(f"NVD returned invalid JSON: {e}") from e
    raise NvdError("NVD lookup failed after retries.")


def extract_cpe_entries(doc: dict) -> list[dict]:
    entries: list[dict] = []

    def add(name, version, cpe):
        if cpe and isinstance(cpe, str) and cpe.startswith("cpe:"):
            entries.append({
                "name": name or "unknown",
                "version": version or "unknown",
                "cpe": cpe,
            })

    if doc.get("bomFormat") == "CycloneDX":
        for component in doc.get("components", []) or []:
            add(component.get("name"), component.get("version"), component.get("cpe"))
        return entries

    if str(doc.get("spdxVersion", "")).startswith("SPDX-2"):
        for package in doc.get("packages", []) or []:
            name = package.get("name")
            version = package.get("versionInfo")
            for ref in package.get("externalRefs", []) or []:
                if ref.get("referenceType") in ("cpe23Type", "cpe22Type", "cpe"):
                    add(name, version, ref.get("referenceLocator"))
        return entries

    if "@graph" in doc:
        for item in doc.get("@graph", []) or []:
            if item.get("type") not in ("software_Package", "Package"):
                continue
            name = item.get("name")
            version = item.get("software_packageVersion") or item.get("versionInfo")
            for ident in item.get("externalIdentifier", []) or []:
                kind = str(ident.get("externalIdentifierType", "")).lower()
                if "cpe" in kind:
                    add(name, version, ident.get("identifier"))
    return entries


def _cvss(cve: dict):
    metrics = cve.get("metrics", {})
    candidates = (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )
    for key, version in candidates:
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return (
                version,
                data.get("baseScore"),
                data.get("baseSeverity") or values[0].get("baseSeverity"),
            )
    return None, None, None


def query_nvd_cpe(
    cpe: str,
    timeout: int = DEFAULT_TIMEOUT,
    api_key: str | None = None,
    min_delay: float | None = None,
) -> list[dict]:
    """Return NVD CVE records matching one exact CPE name, with pagination."""
    delay = (
        DEFAULT_DELAY_WITH_KEY if api_key else DEFAULT_DELAY_WITHOUT_KEY
        if min_delay is None
        else max(0.0, min_delay)
    )
    findings = []
    start_index = 0
    first = True
    while True:
        if not first and delay:
            time.sleep(delay)
        first = False
        params = {
            "cpeName": cpe,
            "startIndex": start_index,
            "resultsPerPage": DEFAULT_RESULTS_PER_PAGE,
        }
        url = f"{NVD_CVE_URL}?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key
        response = _post_json(url, headers, timeout)
        vulnerabilities = response.get("vulnerabilities") or []
        for item in vulnerabilities:
            cve = item.get("cve") or {}
            vid = cve.get("id")
            if not vid:
                continue
            desc = None
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value")
                    break
            cvss_version, score, severity = _cvss(cve)
            findings.append({
                "id": vid,
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "description": desc,
                "cvssVersion": cvss_version,
                "cvssBaseScore": score,
                "cvssSeverity": severity,
            })
        total = int(response.get("totalResults", len(vulnerabilities)) or 0)
        page = int(response.get("resultsPerPage", len(vulnerabilities)) or 0)
        start_index += page
        if not vulnerabilities or start_index >= total:
            break
    return findings


def scan_nvd(
    entries: list[dict],
    timeout: int = DEFAULT_TIMEOUT,
    api_key: str | None = None,
    min_delay: float | None = None,
    on_cpe: Callable[[int, int, str], None] | None = None,
) -> tuple[list[NvdFinding], list[str]]:
    """Scan unique CPEs and return normalized vulnerability findings."""
    unique: dict[str, dict] = {}
    skipped: list[str] = []
    for entry in entries:
        cpe = entry.get("cpe")
        if not cpe:
            skipped.append(entry.get("name", "unknown"))
            continue
        unique.setdefault(cpe, entry)

    findings: list[NvdFinding] = []
    for idx, (cpe, entry) in enumerate(unique.items(), start=1):
        if on_cpe:
            on_cpe(idx, len(unique), cpe)
        for vuln in query_nvd_cpe(cpe, timeout=timeout, api_key=api_key, min_delay=min_delay):
            findings.append(
                NvdFinding(
                    component_name=entry.get("name", "unknown"),
                    version=entry.get("version", "unknown"),
                    cpe=cpe,
                    vulnerability_id=vuln["id"],
                    published=vuln.get("published"),
                    last_modified=vuln.get("lastModified"),
                    description=vuln.get("description"),
                    cvss_version=vuln.get("cvssVersion"),
                    cvss_base_score=vuln.get("cvssBaseScore"),
                    cvss_severity=vuln.get("cvssSeverity"),
                )
            )
    return findings, skipped


def nvd_report(entries, findings, skipped, api_key_used=False):
    return {
        "tool": f"sbom-convert {__version__}",
        "source": "NVD/NIST",
        "endpoint": NVD_CVE_URL,
        "queryMode": "CPE",
        "apiKeyUsed": bool(api_key_used),
        "uniqueCpesQueried": len({e.get("cpe") for e in entries if e.get("cpe")}),
        "componentsSkippedNoCpe": len(skipped),
        "findings": [f.as_dict() for f in findings],
        "warnings": [
            {"code": "NO_CPE", "message": f"No CPE available for component: {name}"}
            for name in skipped
        ],
    }
