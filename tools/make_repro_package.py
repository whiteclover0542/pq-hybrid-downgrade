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
EVIDENCE_MD = "docs/EVIDENCE.md"

REQUIRED_FILES = [
    f"{FAULTINJECT_DIR}/run.py",
    f"{FAULTINJECT_DIR}/aggregate.py",
    f"{FAULTINJECT_DIR}/analyze.py",
    REPRODUCTION_MD,
    PAPER_MD,
    EVIDENCE_MD,
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
        "documents": [REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD],
        "required_files": REQUIRED_FILES,
        "artifacts": REQUIRED_ARTIFACTS,
        "excluded": ("v1.1-diagnose", "v1.1-pre-", "v1.1-preflight"),
        "out": "dist/pq-hybrid-downgrade-v11-repro.zip",
    },
    "v1.2": {
        "raw": "docs/research/baselines/raw/v1.2",
        "documents": [
            REPRODUCTION_MD, PAPER_MD,
            EVIDENCE_MD,
            "tools/v12_a0_smoke.sh",
            "tools/v12_build_openssl_356.sh",
            "tools/v12_boringssl_survey.sh",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v12.py", f"{FAULTINJECT_DIR}/pcap_hello.py",
            f"{FAULTINJECT_DIR}/audit.py", f"{FAULTINJECT_DIR}/analyze.py",
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
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
    "v1.3": {
        "raw": "docs/research/baselines/raw/v1.3",
        "documents": [
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
            "tools/v12_build_openssl_356.sh",
            "tools/v13_build_variants.sh",
            "docs/research/baselines/raw/v1.3-build.log",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v12.py", f"{FAULTINJECT_DIR}/pcap_hello.py",
            f"{FAULTINJECT_DIR}/analyze.py", "tools/v13_build_variants.sh",
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
        ],
        "artifacts": {
            "v1.3 JSON records": (".json", 120),
            "v1.3 PCAPs": (".pcapng", 120),
            "v1.3 client logs": ("-client.log", 120),
            "v1.3 server logs": ("-server.log", 120),
            "v1.3 capture logs": ("-capture.log", 120),
        },
        "excluded": ("v13-smoke", "/raw/v1.1/", "/raw/v1.2/"),
        "out": "dist/pq-hybrid-downgrade-v13-repro.zip",
        "extra_globs": [f"{FAULTINJECT_DIR}/tests/*.py"],
    },
    "v1.4": {
        "raw": "docs/research/baselines/raw/v1.4",
        "documents": [REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD],
        "required_files": [
            f"{FAULTINJECT_DIR}/v12.py", f"{FAULTINJECT_DIR}/pcap_hello.py",
            f"{FAULTINJECT_DIR}/analyze.py", REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
        ],
        "artifacts": {
            "v1.4 JSON records": (".json", 60),
            "v1.4 PCAPs": (".pcapng", 60),
            "v1.4 client logs": ("-client.log", 60),
            "v1.4 server logs": ("-server.log", 60),
            "v1.4 capture logs": ("-capture.log", 60),
        },
        "excluded": ("v14-smoke", "/raw/v1.1/", "/raw/v1.2/", "/raw/v1.3/"),
        "out": "dist/pq-hybrid-downgrade-v14-repro.zip",
        "extra_globs": [f"{FAULTINJECT_DIR}/tests/*.py"],
    },
    "v1.5": {
        "raw": "docs/research/baselines/raw/v1.5",
        "documents": [
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD, "tools/v15_setup.sh",
            "tools/v15/goserver/main.go", "tools/v15/goserver/go.mod",
            "tools/v15/rustserver/Cargo.toml", "tools/v15/rustserver/Cargo.lock",
            "tools/v15/rustserver/src/main.rs", "docs/research/baselines/raw/v1.5-setup.log",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v15.py", f"{FAULTINJECT_DIR}/pcap_hello.py", "tools/v15_setup.sh",
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
        ],
        "artifacts": {
            "v1.5 JSON records": (".json", 105),
            "v1.5 PCAPs": (".pcapng", 105),
            "v1.5 client logs": ("-client.log", 105),
            "v1.5 server logs": ("-server.log", 105),
            "v1.5 capture logs": ("-capture.log", 105),
        },
        "excluded": ("v15-smoke", "/raw/v1.1/", "/raw/v1.2/", "/raw/v1.3/", "/raw/v1.4/"),
        "out": "dist/pq-hybrid-downgrade-v15-repro.zip",
        "extra_globs": [f"{FAULTINJECT_DIR}/tests/*.py"],
    },
    "v1.6": {
        "raw": "docs/research/baselines/raw/v1.6",
        "extra_raw": [
            "docs/research/baselines/raw/v1.5-boringssl-latest",
            "docs/research/baselines/raw/v1.6-direct",
            "docs/research/baselines/raw/v1.6-caddy-2.11.4",
        ],
        "documents": [
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD, "tools/v16_setup.sh",
            "tools/v15/goclient/main.go", "tools/v15/goclient/go.mod",
            "tools/v15/rustserver/Cargo.toml", "tools/v15/rustserver/Cargo.lock",
            "tools/v15/rustserver/src/bin/client.rs", "docs/research/baselines/raw/v1.6-setup.log",
            "docs/research/baselines/raw/nss-ubuntu-patches-20260929.log",
            "tools/v15_build_boringssl_latest.sh", "tools/v15_run_boringssl_latest.sh",
            "tools/v16_run_direct_defaults.sh", "tools/v16_run_caddy_2114.sh",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v16.py", f"{FAULTINJECT_DIR}/v15.py", f"{FAULTINJECT_DIR}/pcap_hello.py",
            "tools/v16_setup.sh", "tools/v15_build_boringssl_latest.sh", "tools/v15_run_boringssl_latest.sh",
            "tools/v16_run_direct_defaults.sh", "tools/v16_run_caddy_2114.sh",
            "docs/research/baselines/raw/nss-ubuntu-patches-20260929.log", REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
        ],
        "artifacts": {
            "v1.6 JSON records": (".json", 36),
            "v1.6 PCAPs": (".pcapng", 36),
            "v1.6 client logs": ("-client.log", 36),
            "v1.6 server logs": ("-server.log", 36),
            "v1.6 capture logs": ("-capture.log", 36),
        },
        "extra_artifacts": {
            "latest BoringSSL JSON records": ("docs/research/baselines/raw/v1.5-boringssl-latest", ".json", 9),
            "direct matrix JSON records": ("docs/research/baselines/raw/v1.6-direct", ".json", 36),
            "latest Caddy JSON records": ("docs/research/baselines/raw/v1.6-caddy-2.11.4", ".json", 36),
        },
        "excluded": ("v16-smoke", "/raw/v1.1/", "/raw/v1.2/", "/raw/v1.3/", "/raw/v1.4/", "/raw/v1.5/"),
        "out": "dist/pq-hybrid-downgrade-v16-repro.zip",
        "extra_globs": [f"{FAULTINJECT_DIR}/tests/*.py"],
    },
    "v1.7": {
        "raw": "docs/research/baselines/raw/v1.7",
        "extra_raw": ["docs/research/baselines/raw/v1.7-openssl36"],
        "documents": [
            REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD, "tools/v17_setup.sh", "tools/v13_build_variants.sh",
            "docs/research/baselines/raw/v1.7-setup.log", "docs/research/baselines/raw/v1.7-build36.log",
            "docs/research/baselines/raw/v1.7-ldd36.log", "docs/research/baselines/raw/v1.7-tshark-version.log",
            "docs/research/baselines/raw/v1.7-tshark-verbose-audit.json",
        ],
        "required_files": [
            f"{FAULTINJECT_DIR}/v17.py", f"{FAULTINJECT_DIR}/v16.py", f"{FAULTINJECT_DIR}/v12.py",
            f"{FAULTINJECT_DIR}/analyze.py", "tools/v17_setup.sh", "tools/v13_build_variants.sh",
            "docs/research/baselines/raw/v1.7-tshark-verbose-audit.json", REPRODUCTION_MD, PAPER_MD, EVIDENCE_MD,
        ],
        "artifacts": {
            "v1.7 JSON records": (".json", 15),
            "v1.7 PCAPs": (".pcapng", 15),
            "v1.7 client logs": ("-client.log", 15),
            "v1.7 server logs": ("-server.log", 15),
            "v1.7 capture logs": ("-capture.log", 15),
        },
        "extra_artifacts": {
            "OpenSSL 3.6 causal-isolation JSON records": ("docs/research/baselines/raw/v1.7-openssl36", ".json", 60),
            "OpenSSL 3.6 causal-isolation PCAPs": ("docs/research/baselines/raw/v1.7-openssl36", ".pcapng", 60),
        },
        "excluded": ("v17-smoke", "/raw/v1.1/", "/raw/v1.2/", "/raw/v1.3/", "/raw/v1.4/", "/raw/v1.5/", "/raw/v1.6/"),
        "out": "dist/pq-hybrid-downgrade-v17-repro.zip",
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
    for raw_dir in config.get("extra_raw", []):
        members.extend(sorted((REPO_ROOT / raw_dir).glob("*")))
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
    for label, (raw_dir, suffix, minimum) in config.get("extra_artifacts", {}).items():
        if sum(name.startswith(f"{raw_dir}/") and name.endswith(suffix) for name in names) < minimum:
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
