import zipfile
from pathlib import Path

from make_repro_package import build_zip, verify_zip

REPO = Path(__file__).resolve().parents[3]


def test_v15_zip_contains_the_comparison_and_server_sources(tmp_path):
    zip_path = build_zip(tmp_path / "v15.zip", package="v1.5")
    names = zipfile.ZipFile(zip_path).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.5/" in n for n in names) == 105
    assert "tools/v15/goserver/main.go" in names
    assert "tools/v15/rustserver/src/main.rs" in names
    assert verify_zip(zip_path, package="v1.5") == (True, [])


def test_committed_v15_zip_matches_repository_docs():
    with zipfile.ZipFile(REPO / "dist/pq-hybrid-downgrade-v15-repro.zip") as zf:
        for name in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(name) == (REPO / name).read_bytes(), name
