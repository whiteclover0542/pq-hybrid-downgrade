"""Bundle and verify the validated v1.1 reproduction evidence package."""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

RAW_V11_DIR = "docs/research/baselines/raw/v1.1"
FAULTINJECT_DIR = "tools/faultinject"
REPRODUCTION_MD = "docs/research/REPRODUCTION.md"
PAPER_MD = "docs/PAPER.md"
V11_DESIGN_MD = "docs/research/2026-09-23-v1.1-hrr-downgrade-design.md"
P2_SUMMARY_MD = ".planning/phases/07-v11-tooling/07-02-SUMMARY.md"
P3_ANALYSIS_MD = "docs/research/v1.1-p3-analysis.md"

REQUIRED_FILES = [
    f"{FAULTINJECT_DIR}/run.py",
    f"{FAULTINJECT_DIR}/aggregate.py",
    f"{FAULTINJECT_DIR}/analyze.py",
    REPRODUCTION_MD,
    PAPER_MD,
    V11_DESIGN_MD,
    P2_SUMMARY_MD,
    P3_ANALYSIS_MD,
]

REQUIRED_ARTIFACTS = {
    "v1.1 JSON records": (".json", 90),
    "v1.1 PCAPs": (".pcapng", 90),
    "v1.1 client logs": ("-client.log", 90),
    "v1.1 capture logs": ("-capture.log", 90),
    "v1.1 proxy logs": ("-proxy.log", 30),
}


def build_zip(out_path: Path) -> Path:
    """Bundle final v1.1 evidence and its review materials with relative paths."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    members: list[Path] = []
    members.extend(sorted((REPO_ROOT / RAW_V11_DIR).glob("*")))
    members.extend(sorted((REPO_ROOT / FAULTINJECT_DIR).glob("*.py")))
    members.append(REPO_ROOT / REPRODUCTION_MD)
    members.append(REPO_ROOT / PAPER_MD)
    members.append(REPO_ROOT / V11_DESIGN_MD)
    members.append(REPO_ROOT / P2_SUMMARY_MD)
    members.append(REPO_ROOT / P3_ANALYSIS_MD)

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

    v11_names = [name for name in names if name.startswith(f"{RAW_V11_DIR}/")]
    for label, (suffix, minimum) in REQUIRED_ARTIFACTS.items():
        if sum(name.endswith(suffix) for name in v11_names) < minimum:
            missing.append(label)

    excluded_markers = ("v1.1-diagnose", "v1.1-pre-", "v1.1-preflight")
    if any(marker in name for name in names for marker in excluded_markers):
        missing.append("excluded v1.1 diagnostic or partial data")

    return (len(missing) == 0, missing)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the single-ZIP reproduction package")
    parser.add_argument("--out", default=None,
                        help="output ZIP path, relative to cwd "
                             "(default: <repo_root>/dist/pq-hybrid-downgrade-v11-repro.zip)")
    args = parser.parse_args()

    # --out is a normal path relative to the caller's cwd (e.g. `../dist/x.zip`
    # when run from tools/); only the unset default is anchored to the repo root.
    out_path = Path(args.out) if args.out else REPO_ROOT / "dist/pq-hybrid-downgrade-v11-repro.zip"

    built = build_zip(out_path)
    ok, missing = verify_zip(built)
    print(f"built: {built}")
    print(f"verify: ok={ok} missing={missing}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
