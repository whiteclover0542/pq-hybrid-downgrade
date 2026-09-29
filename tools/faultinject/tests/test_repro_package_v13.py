import zipfile
from pathlib import Path

from make_repro_package import build_zip, verify_zip

REPO = Path(__file__).resolve().parents[3]


def test_v13_zip_contains_the_variant_matrix_and_build_recipe(tmp_path):
    zip_path = build_zip(tmp_path / "v13.zip", package="v1.3")
    names = zipfile.ZipFile(zip_path).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.3/" in n for n in names) == 120
    assert "tools/v13_build_variants.sh" in names
    assert "docs/research/baselines/raw/v1.3-build.log" in names
    assert not any("/raw/v1.2/" in n or "/raw/v1.1/" in n for n in names)
    assert verify_zip(zip_path, package="v1.3") == (True, [])


def test_committed_v13_zip_matches_repository_docs():
    with zipfile.ZipFile(REPO / "dist/pq-hybrid-downgrade-v13-repro.zip") as zf:
        for name in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(name) == (REPO / name).read_bytes(), name
