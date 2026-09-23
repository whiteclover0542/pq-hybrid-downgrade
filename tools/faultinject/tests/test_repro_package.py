import zipfile
from pathlib import Path
from make_repro_package import build_zip, verify_zip

def test_zip_contains_core_artifacts(tmp_path):
    z = build_zip(tmp_path / "repro.zip")
    names = zipfile.ZipFile(z).namelist()
    assert any(n.endswith("manifest.csv") for n in names)
    assert any("faultinject/run.py" in n for n in names)
    assert any(n.endswith("REPRODUCTION.md") for n in names)
    assert any("raw/phase-4/" in n and n.endswith(".json") for n in names)

def test_verify_zip_reports_ok(tmp_path):
    z = build_zip(tmp_path / "repro.zip")
    ok, missing = verify_zip(z)
    assert ok is True
    assert missing == []
