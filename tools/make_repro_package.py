"""Bundle and verify the validated milestone reproduction packages."""
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

PACKAGES = {
    "v1.1": {
        "raw": RAW_V11_DIR,
        "documents": [REPRODUCTION_MD, PAPER_MD, V11_DESIGN_MD, P2_SUMMARY_MD, P3_ANALYSIS_MD],
        "required_files": REQUIRED_FILES,
        "artifacts": REQUIRED_ARTIFACTS,
        "excluded": ("v1.1-diagnose", "v1.1-pre-", "v1.1-preflight"),
        "out": "dist/pq-hybrid-downgrade-v11-repro.zip",
    },
    "v1.2": {
        "raw": "docs/research/baselines/raw/v1.2",
        "documents": [
            REPRODUCTION_MD, PAPER_MD,
            "docs/superpowers/specs/2026-09-28-v12-cve-tuple-hrr-design.md",
            "docs/research/v1.2-a0-environment.md",
            "docs/research/v1.2-analysis.md",
            "docs/research/v1.2-normative-analysis.md",
            "docs/research/v1.2-audit-v1.1-recompute.md",
            "tools/v12_a0_smoke.sh",
            "tools/v12_build_openssl_356.sh",
            "tools/v12_boringssl_survey.sh",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v12.py", f"{FAULTINJECT_DIR}/pcap_hello.py",
            f"{FAULTINJECT_DIR}/audit.py", f"{FAULTINJECT_DIR}/analyze.py",
            REPRODUCTION_MD, PAPER_MD, "docs/research/v1.2-analysis.md",
        ],
        "artifacts": {
            "v1.2 JSON records": (".json", 60),
            "v1.2 PCAPs": (".pcapng", 60),
            "v1.2 client logs": ("-client.log", 60),
            "v1.2 server logs": ("-server.log", 60),
            "v1.2 capture logs": ("-capture.log", 60),
        },
        "excluded": ("v1.2-s4", "v12-smoke", "/raw/v1.1/"),
        "out": "dist/pq-hybrid-downgrade-v12-repro.zip",
        "extra_globs": [f"{FAULTINJECT_DIR}/tests/*.py"],
    },
}


def build_zip(out_path: Path, package: str = "v1.1") -> Path:
    """Bundle one milestone's final evidence and its review materials with relative paths."""
    config = PACKAGES[package]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    members: list[Path] = []
    members.extend(sorted((REPO_ROOT / config["raw"]).glob("*")))
    members.extend(sorted((REPO_ROOT / FAULTINJECT_DIR).glob("*.py")))
    members.extend(REPO_ROOT / document for document in config["documents"])
    for pattern in config.get("extra_globs", []):
        members.extend(sorted(REPO_ROOT.glob(pattern)))

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member in members:
            if member.is_file():
                zf.write(member, member.relative_to(REPO_ROOT).as_posix())
    return out_path


def verify_zip(zip_path: Path, package: str = "v1.1") -> tuple[bool, list[str]]:
    """Check that an unpacked-anywhere ZIP still has all required files."""
    config = PACKAGES[package]
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()

    missing = [required for required in config["required_files"] if required not in names]

    raw_names = [name for name in names if name.startswith(f"{config['raw']}/")]
    for label, (suffix, minimum) in config["artifacts"].items():
        if sum(name.endswith(suffix) for name in raw_names) < minimum:
            missing.append(label)

    if any(marker in name for name in names for marker in config["excluded"]):
        missing.append(f"excluded {package} diagnostic or partial data")

    return (len(missing) == 0, missing)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the single-ZIP reproduction package")
    parser.add_argument("--package", choices=sorted(PACKAGES), default="v1.1")
    parser.add_argument("--out", default=None,
                        help="output ZIP path, relative to cwd (default: <repo_root>/<package default>)")
    args = parser.parse_args()

    # --out is a normal path relative to the caller's cwd (e.g. `../dist/x.zip`
    # when run from tools/); only the unset default is anchored to the repo root.
    out_path = Path(args.out) if args.out else REPO_ROOT / PACKAGES[args.package]["out"]

    built = build_zip(out_path, args.package)
    ok, missing = verify_zip(built, args.package)
    print(f"built: {built}")
    print(f"verify: ok={ok} missing={missing}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
