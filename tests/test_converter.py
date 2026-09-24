# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
import pytest

from sbom_converter.cli import main
from sbom_converter.core import (
    ConversionError,
    UnsupportedInput,
    ValidationError,
    basic_validate,
    convert,
    detect,
    validate_output,
)


def spdx():
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "demo",
        "documentNamespace": "https://example.test/demo",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Person: Test"]},
        "packages": [{"name": "libfoo", "SPDXID": "SPDXRef-libfoo", "versionInfo": "1.2.3", "licenseConcluded": "MIT"}],
    }


def cdx():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": "library", "bom-ref": "libfoo", "name": "libfoo", "version": "1.2.3"}],
    }


def test_detect():
    assert detect(spdx()) == "spdx-2.3"
    assert detect(cdx()) == "cyclonedx-1.6"


def test_detect_rejects_non_dict():
    with pytest.raises(UnsupportedInput):
        detect(["not", "a", "document"])


def test_detect_rejects_unknown_format():
    with pytest.raises(UnsupportedInput):
        detect({"foo": "bar"})


def test_spdx_to_cdx17():
    out, report = convert(spdx(), "cdx-1.7")
    assert out["specVersion"] == "1.7"
    assert report.stats["components"] == 1


def test_cdx_to_spdx301():
    out, _ = convert(cdx(), "spdx-3.0.1")
    assert out["@context"].endswith("spdx-context.jsonld")


def test_cdx_to_spdx31_warns_experimental():
    _, report = convert(cdx(), "spdx-3.1")
    assert any(w.code == "EXPERIMENTAL_TARGET" for w in report.warnings)


def test_cdx_to_cdx17_roundtrip():
    out, report = convert(cdx(), "cdx-1.7")
    assert out["specVersion"] == "1.7"
    assert any(w.code == "UPCONVERT" for w in report.warnings)


def test_basic_validate_spdx_missing_field():
    doc = spdx()
    del doc["dataLicense"]
    with pytest.raises(ValidationError):
        basic_validate(doc, "spdx-2.3")


def test_basic_validate_spdx_wrong_type():
    doc = spdx()
    doc["packages"] = "not-a-list"
    with pytest.raises(ValidationError):
        basic_validate(doc, "spdx-2.3")


def test_basic_validate_cdx_missing_header():
    with pytest.raises(ValidationError):
        basic_validate({"bomFormat": "CycloneDX"}, "cyclonedx-")


def test_basic_validate_spdx3_requires_graph():
    with pytest.raises(ValidationError):
        basic_validate({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}, "spdx-3.0.1")


def test_convert_unsupported_target():
    with pytest.raises(ConversionError):
        convert(spdx(), "not-a-real-target")


def test_convert_unimplemented_path():
    doc = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [{"type": "SpdxDocument", "spdxId": "SPDXRef-DOCUMENT"}],
    }
    with pytest.raises(ConversionError):
        convert(doc, "cdx-1.7")


def test_strict_mode_rejects_warnings():
    with pytest.raises(ConversionError):
        convert(cdx(), "spdx-3.1", strict=True)


def test_cli_info(capsys):
    import json
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "in.json"
        path.write_text(json.dumps(spdx()))
        assert main([str(path), "--info"]) == 0
        assert capsys.readouterr().out.strip() == "spdx-2.3"


def test_cli_validate(capsys):
    import json
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "in.json"
        path.write_text(json.dumps(spdx()))
        assert main([str(path), "--validate"]) == 0
        assert "OK: spdx-2.3" in capsys.readouterr().out


def test_cli_convert_writes_output(tmp_path):
    import json

    in_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    in_path.write_text(json.dumps(spdx()))
    assert main([str(in_path), "--to", "cdx-1.7", "-o", str(out_path)]) == 0
    out = json.loads(out_path.read_text())
    assert out["specVersion"] == "1.7"


def test_cli_missing_input_errors():
    with pytest.raises(SystemExit):
        main([])


def test_cli_invalid_json_returns_error_code(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    assert main([str(bad)]) == 3
    assert "ERROR" in capsys.readouterr().err


def test_cli_missing_file_returns_error_code(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.json"
    assert main([str(missing)]) == 3
    assert "ERROR" in capsys.readouterr().err


def test_cli_unsupported_input_returns_error_code(tmp_path, capsys):
    import json

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"foo": "bar"}))
    assert main([str(bad)]) == 2
    assert "ERROR" in capsys.readouterr().err


def test_validate_output_cdx17_valid():
    out, _ = convert(spdx(), "cdx-1.7")
    assert validate_output(out, "cdx-1.7") is True


def test_validate_output_cdx17_missing_serialnumber():
    out, _ = convert(spdx(), "cdx-1.7")
    del out["serialNumber"]
    with pytest.raises(ValidationError, match="serialNumber"):
        validate_output(out, "cdx-1.7")


def test_validate_output_cdx17_invalid_specversion():
    out, _ = convert(spdx(), "cdx-1.7")
    out["specVersion"] = "1.6"
    with pytest.raises(ValidationError, match="1.7"):
        validate_output(out, "cdx-1.7")


def test_validate_output_cdx17_components_not_list():
    out, _ = convert(spdx(), "cdx-1.7")
    out["components"] = "not-a-list"
    with pytest.raises(ValidationError, match="components.*list"):
        validate_output(out, "cdx-1.7")


def test_validate_output_cdx17_component_missing_name():
    out, _ = convert(spdx(), "cdx-1.7")
    del out["components"][0]["name"]
    with pytest.raises(ValidationError, match="name"):
        validate_output(out, "cdx-1.7")


def test_validate_output_spdx301_valid():
    out, _ = convert(cdx(), "spdx-3.0.1")
    assert validate_output(out, "spdx-3.0.1") is True


def test_validate_output_spdx301_missing_context():
    out, _ = convert(cdx(), "spdx-3.0.1")
    del out["@context"]
    with pytest.raises(ValidationError, match="@context"):
        validate_output(out, "spdx-3.0.1")


def test_validate_output_spdx301_graph_not_list():
    out, _ = convert(cdx(), "spdx-3.0.1")
    out["@graph"] = "not-a-list"
    with pytest.raises(ValidationError, match="@graph"):
        validate_output(out, "spdx-3.0.1")


def test_validate_output_spdx301_empty_graph():
    out, _ = convert(cdx(), "spdx-3.0.1")
    out["@graph"] = []
    with pytest.raises(ValidationError, match="not be empty"):
        validate_output(out, "spdx-3.0.1")


def test_validate_output_spdx301_graph_item_missing_type():
    out, _ = convert(cdx(), "spdx-3.0.1")
    del out["@graph"][0]["type"]
    with pytest.raises(ValidationError, match="type"):
        validate_output(out, "spdx-3.0.1")


def test_validate_output_not_dict():
    with pytest.raises(ValidationError, match="JSON object"):
        validate_output([], "cdx-1.7")
