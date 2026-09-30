import zipfile
from pathlib import Path

from make_repro_package import build_zip, verify_zip

REPO = Path(__file__).resolve().parents[3]


def test_v18_zip_contains_final_survey_and_c3_controls_but_not_diagnostics(tmp_path):
    zip_path = build_zip(tmp_path / "v18.zip", package="v1.8")
    names = zipfile.ZipFile(zip_path).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.8/" in n for n in names) == 25
    assert sum(n.endswith(".json") and "/raw/v1.8-e8/" in n for n in names) == 16
    assert not any("v1.8-diagnose" in n for n in names)
    assert "tools/v18_run_e8_order.sh" in names
    assert verify_zip(zip_path, package="v1.8") == (True, [])


def test_committed_v18_zip_matches_repository_docs():
    with zipfile.ZipFile(REPO / "dist/pq-hybrid-downgrade-v18-repro.zip") as zf:
        for name in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(name) == (REPO / name).read_bytes(), name
