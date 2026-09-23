"""Bundle a single-ZIP reproduction package (raw phase-4 data + fault-injection
code + procedure docs) and verify one unpacks with all required artifacts.
"""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

RAW_PHASE4_DIR = "docs/research/baselines/raw/phase-4"
FAULTINJECT_DIR = "tools/faultinject"
REPRODUCTION_MD = "docs/research/REPRODUCTION.md"
PHASE4_EXECUTION_MD = "docs/research/phase-4-execution.md"

REQUIRED_FILES = [
    f"{RAW_PHASE4_DIR}/manifest.csv",
    f"{FAULTINJECT_DIR}/run.py",
    f"{FAULTINJECT_DIR}/aggregate.py",
    f"{FAULTINJECT_DIR}/analyze.py",
    REPRODUCTION_MD,
]
MIN_RAW_JSON_COUNT = 60


def build_zip(out_path: Path) -> Path:
    """Bundle raw phase-4 data, faultinject source, and procedure docs into
    a single ZIP, stored with repo-root-relative paths so it unpacks safely
    at any location."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    members: list[Path] = []
    members.extend(sorted((REPO_ROOT / RAW_PHASE4_DIR).glob("*")))
    members.extend(sorted((REPO_ROOT / FAULTINJECT_DIR).glob("*.py")))
    members.append(REPO_ROOT / REPRODUCTION_MD)
    members.append(REPO_ROOT / PHASE4_EXECUTION_MD)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member in members:
            if member.is_file():
                zf.write(member, member.relative_to(REPO_ROOT).as_posix())
    return out_path


def verify_zip(zip_path: Path) -> tuple[bool, list[str]]:
    """Check that an unpacked-anywhere ZIP still has all required files."""
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()

    missing = [required for required in REQUIRED_FILES if required not in names]

    raw_json_count = sum(
        1 for n in names if f"{RAW_PHASE4_DIR}/" in n and n.endswith(".json")
    )
    if raw_json_count < MIN_RAW_JSON_COUNT:
        missing.append(
            f"{RAW_PHASE4_DIR}/*.json (found {raw_json_count}, need >= {MIN_RAW_JSON_COUNT})"
        )

    return (len(missing) == 0, missing)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the single-ZIP reproduction package")
    parser.add_argument("--out", default=None,
                        help="output ZIP path, relative to cwd "
                             "(default: <repo_root>/dist/pq-hybrid-downgrade-repro.zip)")
    args = parser.parse_args()

    # --out is a normal path relative to the caller's cwd (e.g. `../dist/x.zip`
    # when run from tools/); only the unset default is anchored to the repo root.
    out_path = Path(args.out) if args.out else REPO_ROOT / "dist/pq-hybrid-downgrade-repro.zip"

    built = build_zip(out_path)
    ok, missing = verify_zip(built)
    print(f"built: {built}")
    print(f"verify: ok={ok} missing={missing}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
