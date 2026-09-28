import zipfile

from make_repro_package import build_zip, verify_zip


def test_zip_contains_core_artifacts(tmp_path):
    z = build_zip(tmp_path / "repro.zip")
    names = zipfile.ZipFile(z).namelist()
    assert "docs/PAPER.md" in names
    assert "docs/research/REPRODUCTION.md" in names
    assert "docs/research/2026-09-23-v1.1-hrr-downgrade-design.md" in names
    assert ".planning/phases/07-v11-tooling/07-02-SUMMARY.md" in names
    assert "docs/research/v1.1-p3-analysis.md" in names
    assert "tools/faultinject/run.py" in names
    assert sum(n.endswith(".json") and "/raw/v1.1/" in n for n in names) == 90
    assert sum(n.endswith(".pcapng") and "/raw/v1.1/" in n for n in names) == 90
    assert sum(n.endswith("-client.log") and "/raw/v1.1/" in n for n in names) == 90
    assert sum(n.endswith("-capture.log") and "/raw/v1.1/" in n for n in names) == 90
    assert sum(n.endswith("-proxy.log") and "/raw/v1.1/" in n for n in names) == 30
    assert not any("v1.1-diagnose" in n or "v1.1-pre-" in n or "v1.1-preflight" in n for n in names)


def test_verify_zip_reports_ok(tmp_path):
    z = build_zip(tmp_path / "repro.zip")
    ok, missing = verify_zip(z)
    assert ok is True
    assert missing == []


def test_verify_zip_requires_each_v11_artifact_class(tmp_path):
    empty_zip = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_zip, "w"):
        pass

    ok, missing = verify_zip(empty_zip)

    assert ok is False
    assert set(missing) >= {
        "v1.1 JSON records",
        "v1.1 PCAPs",
        "v1.1 client logs",
        "v1.1 capture logs",
        "v1.1 proxy logs",
    }
