import zipfile
from pathlib import Path

from make_repro_package import build_zip, verify_zip

REPO = Path(__file__).resolve().parents[3]


def test_v17_zip_contains_browsers_trace_and_openssl36(tmp_path):
    zip_path = build_zip(tmp_path / "v17.zip", package="v1.7")
    names = zipfile.ZipFile(zip_path).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.7/" in n for n in names) == 15
    assert sum(n.endswith(".json") and "/raw/v1.7-openssl36/" in n for n in names) == 60
    assert "docs/research/baselines/raw/v1.7-tshark-verbose-audit.json" in names
    assert "tools/v17_setup.sh" in names
    assert verify_zip(zip_path, package="v1.7") == (True, [])


def test_committed_v17_zip_matches_repository_docs():
    with zipfile.ZipFile(REPO / "dist/pq-hybrid-downgrade-v17-repro.zip") as zf:
        for name in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(name) == (REPO / name).read_bytes(), name
