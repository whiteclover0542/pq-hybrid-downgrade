import zipfile

from make_repro_package import build_zip, verify_zip


def test_v12_zip_contains_the_required_matrix_and_documents(tmp_path):
    names = zipfile.ZipFile(build_zip(tmp_path / "v12.zip", package="v1.2")).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.2/" in n for n in names) == 60
    assert sum(n.endswith(".pcapng") and "/raw/v1.2/" in n for n in names) == 60
    assert "docs/research/v1.2-analysis.md" in names
    assert "docs/research/v1.2-normative-analysis.md" in names
    assert "docs/research/v1.2-a0-environment.md" in names
    assert "docs/superpowers/specs/2026-09-28-v12-cve-tuple-hrr-design.md" in names
    assert "tools/faultinject/v12.py" in names
    assert not any("/raw/v1.2-s4/" in n or "/raw/v1.1/" in n for n in names)


def test_v12_zip_verifies(tmp_path):
    assert verify_zip(build_zip(tmp_path / "v12.zip", package="v1.2"), package="v1.2") == (True, [])
