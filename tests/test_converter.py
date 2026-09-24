# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
from sbom_converter.core import detect, convert

def spdx():
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"demo","documentNamespace":"https://example.test/demo","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Person: Test"]},"packages":[{"name":"libfoo","SPDXID":"SPDXRef-libfoo","versionInfo":"1.2.3","licenseConcluded":"MIT"}]}

def cdx():
    return {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"libfoo","name":"libfoo","version":"1.2.3"}]}

def test_detect():
    assert detect(spdx())=="spdx-2.3"
    assert detect(cdx())=="cyclonedx-1.6"

def test_spdx_to_cdx17():
    out,_=convert(spdx(),"cdx-1.7"); assert out["specVersion"]=="1.7"

def test_cdx_to_spdx301():
    out,_=convert(cdx(),"spdx-3.0.1"); assert out["@context"].endswith("spdx-context.jsonld")
