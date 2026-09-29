import zipfile
from pathlib import Path

from make_repro_package import build_zip, verify_zip

REPO = Path(__file__).resolve().parents[3]


def test_v14_zip_contains_the_hybrid_first_matrix(tmp_path):
    zip_path = build_zip(tmp_path / "v14.zip", package="v1.4")
    names = zipfile.ZipFile(zip_path).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.4/" in n for n in names) == 60
    assert verify_zip(zip_path, package="v1.4") == (True, [])


def test_committed_v14_zip_matches_repository_docs():
    with zipfile.ZipFile(REPO / "dist/pq-hybrid-downgrade-v14-repro.zip") as zf:
        for name in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(name) == (REPO / name).read_bytes(), name
