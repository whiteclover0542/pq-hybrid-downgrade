import zipfile

from make_repro_package import REPO_ROOT, build_zip, verify_zip

V12_ZIP = REPO_ROOT / "dist/pq-hybrid-downgrade-v12-repro.zip"


def test_v12_zip_contains_the_required_matrix_and_documents(tmp_path):
    names = zipfile.ZipFile(build_zip(tmp_path / "v12.zip", package="v1.2")).namelist()

    assert sum(n.endswith(".json") and "/raw/v1.2/" in n for n in names) == 60
    assert sum(n.endswith(".pcapng") and "/raw/v1.2/" in n for n in names) == 60
    assert "docs/EVIDENCE.md" in names
    assert "tools/faultinject/v12.py" in names
    assert not any("/raw/v1.2-s4/" in n or "/raw/v1.1/" in n for n in names)


def test_v12_zip_verifies(tmp_path):
    assert verify_zip(build_zip(tmp_path / "v12.zip", package="v1.2"), package="v1.2") == (True, [])


def test_committed_v12_zip_matches_repository_docs():
    with zipfile.ZipFile(V12_ZIP) as zf:
        for doc in ("docs/PAPER.md", "docs/EVIDENCE.md", "docs/research/REPRODUCTION.md"):
            assert zf.read(doc) == (REPO_ROOT / doc).read_bytes()
