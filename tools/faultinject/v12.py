from __future__ import annotations

import argparse
import hashlib
import os
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.audit import audit_record
from faultinject.harness import ScenarioSpec, detect_hrr, run_scenario
from faultinject.pcap_hello import client_precondition, group_name, summarize_hellos
from faultinject.record import RunRecord

PHASE2_ROOT = "/root/pq-hybrid-phase2"
V12_PORT = 8545
HYGIENE_PORTS = (8543, 8544, 2323, 9543, 9544, 9555, V12_PORT)
CLIENT_GROUPS = "X25519:X25519MLKEM768"
SERVER_VERSIONS = ("3.5.5", "3.5.6")
SERVER_SETTINGS = {
    "S1": "X25519MLKEM768:X25519",
    "S2": "X25519MLKEM768/X25519",
    "S3": "DEFAULT",
    "S4": None,
}
REQUIRED_SETTINGS = ("S1", "S2", "S3")
_PREFIX = {
    "3.5.5": f"{PHASE2_ROOT}/install/openssl",
    "3.5.6": f"{PHASE2_ROOT}/install/openssl-3.5.6",
}
_RESIDUAL_PATTERN = r"openssl s_server|openssl s_client|bssl (server|client)|sshd -D|tshark -i lo"


def v12_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.2"


def v12_paths() -> dict[str, str]:
    return {
        "client_bin": f"{_PREFIX['3.5.5']}/bin/openssl",
        "server_bin_3.5.5": f"{_PREFIX['3.5.5']}/bin/openssl",
        "server_bin_3.5.6": f"{_PREFIX['3.5.6']}/bin/openssl",
        "cert": f"{PHASE2_ROOT}/openssl/apps/server.pem",
    }


def native_environment(version: str, base: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    environment.pop("OPENSSL_MODULES", None)
    environment["LD_LIBRARY_PATH"] = f"{_PREFIX[version]}/lib64"
    environment["OPENSSL_CONF"] = "/dev/null"
    return environment


def v12_spec(
    version: str, setting: str, repetition: int, out_dir: Path, paths: dict[str, str]
) -> ScenarioSpec:
    groups = SERVER_SETTINGS[setting]
    server_cmd = [
        paths[f"server_bin_{version}"], "s_server", "-tls1_3", "-www", "-provider", "default",
        "-accept", str(V12_PORT), "-cert", paths["cert"],
        *(["-groups", groups] if groups else []),
    ]
    client_cmd = [
        paths["client_bin"], "s_client", "-tls1_3", "-state", "-msg", "-provider", "default",
        "-connect", f"127.0.0.1:{V12_PORT}", "-groups", CLIENT_GROUPS,
    ]
    return ScenarioSpec(
        impl="openssl",
        fault_type="server-setting",
        repetition=repetition,
        condition=f"{version}-{setting}",
        server_cmd=server_cmd,
        client_cmd=client_cmd,
        listen_port=V12_PORT,
        env=native_environment("3.5.5"),
        out_dir=out_dir,
        capture_traffic=True,
        advertised_hybrid=True,
        server_env=native_environment(version),
    )


def v12_specs(
    repetitions: int,
    output_dir: Path | None = None,
    settings: tuple[str, ...] = REQUIRED_SETTINGS,
    paths: dict[str, str] | None = None,
) -> list[ScenarioSpec]:
    out_dir = output_dir or v12_output_dir()
    paths = paths or v12_paths()
    return [
        v12_spec(version, setting, repetition, out_dir, paths)
        for repetition in range(1, repetitions + 1)
        for version in SERVER_VERSIONS
        for setting in settings
    ]


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def preflight_v12(paths: dict[str, str], runner=subprocess.run, port_free=_port_free) -> tuple[bool, str]:
    for key, value in paths.items():
        if not Path(value).exists():
            return False, f"missing: {key} -> {value}"
    binaries = {
        "client (3.5.5)": (paths["client_bin"], "3.5.5"),
        **{f"server {version}": (paths[f"server_bin_{version}"], version) for version in SERVER_VERSIONS},
    }
    for label, (binary, version) in binaries.items():
        environment = native_environment(version)
        run = lambda *args: runner([binary, *args], env=environment, capture_output=True, text=True).stdout
        reported = run("version")
        if not reported.startswith(f"OpenSSL {version} ") or f"(Library: OpenSSL {version} " not in reported:
            return False, f"{label} reports {reported.strip()!r}, expected OpenSSL {version}"
        providers = run("list", "-providers", "-provider", "default")
        if "default" not in providers or "oqsprovider" in providers:
            return False, f"{label} is not native-only: {providers.strip()!r}"
        if "X25519MLKEM768" not in run("list", "-tls-groups", "-tls1_3"):
            return False, f"{label} does not list X25519MLKEM768 natively"
    busy = [port for port in HYGIENE_PORTS if not port_free(port)]
    if busy:
        return False, f"ports in use: {busy}"
    residual = runner(["pgrep", "-a", "-f", _RESIDUAL_PATTERN], capture_output=True, text=True).stdout.strip()
    if residual:
        return False, f"residual processes: {residual}"
    return True, "ok"


def sha256_file(path: Path) -> str | None:
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def provenance_for(spec: ScenarioSpec, paths: dict[str, str], hashes: dict[str, str | None]) -> dict:
    version, setting = spec.condition.rsplit("-", 1)
    keep = ("LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES")
    return {
        "server_version": version,
        "server_setting": setting,
        "server_groups_arg": SERVER_SETTINGS[setting] or "(omitted)",
        "server_bin": paths[f"server_bin_{version}"],
        "server_bin_sha256": hashes.get(f"server_bin_{version}"),
        "client_bin": paths["client_bin"],
        "client_bin_sha256": hashes.get("client_bin"),
        "client_groups_arg": CLIENT_GROUPS,
        "server_preference": "OpenSSL default (client preference; -serverpref not set)",
        "server_env": {key: spec.server_env.get(key) for key in keep},
        "client_env": {key: spec.env.get(key) for key in keep},
        "server_cmd": spec.server_cmd,
        "client_cmd": spec.client_cmd,
    }


def evaluate_v12(record: RunRecord, run_dir: Path, provenance: dict, runner=subprocess.run) -> RunRecord:
    run_dir = Path(run_dir)
    metrics = replace(record.metrics)
    pcap_name = record.artifacts.get("pcap")
    pcap = run_dir / pcap_name if pcap_name else None
    if pcap is not None and pcap.is_file() and pcap.stat().st_size > 0:
        summary = summarize_hellos(pcap.read_bytes())
        metrics.hrr_pcap_present = summary.hrr_count > 0
        metrics.server_hello_count = summary.server_hello_count
        metrics.final_negotiated_group = group_name(summary.final_group)
        metrics.client_precondition_verified = client_precondition(summary)
    else:
        metrics.hrr_pcap_present = None
        metrics.server_hello_count = None
        metrics.final_negotiated_group = None
        metrics.client_precondition_verified = False
    client_log = run_dir / record.artifacts["client_log"]
    metrics.hrr_log_present = (
        detect_hrr(client_log.read_text(encoding="utf-8", errors="replace")) if client_log.is_file() else None
    )
    metrics.downgrade_flagged = None  # v1.1's hard-coded value; v1.2 measures record.audit instead
    evaluated = replace(
        record,
        metrics=metrics,
        manipulation_verified=metrics.client_precondition_verified is True,
        provenance=provenance,
        audit=audit_record(record, run_dir, runner),
    )
    evaluated.to_json_path(run_dir)
    return evaluated


def run_v12(
    repetitions: int,
    output_dir: Path | None = None,
    settings: tuple[str, ...] = REQUIRED_SETTINGS,
    runner=subprocess.run,
    scenario_runner=run_scenario,
) -> list[RunRecord]:
    out_dir = Path(output_dir or v12_output_dir())
    if out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    paths = v12_paths()
    hashes = {key: sha256_file(Path(value)) for key, value in paths.items() if key != "cert"}
    return [
        evaluate_v12(scenario_runner(spec), out_dir, provenance_for(spec, paths, hashes), runner)
        for spec in v12_specs(repetitions, out_dir, settings, paths)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the v1.2 OpenSSL server-setting matrix")
    parser.add_argument("--repeat", type=int, required=True, metavar="N", help="repetitions per combination")
    parser.add_argument("--settings", default=",".join(REQUIRED_SETTINGS),
                        help="comma-separated subset of S1,S2,S3,S4 (default: S1,S2,S3)")
    parser.add_argument("--output-dir", type=Path, metavar="PATH",
                        help="write records here instead of raw/v1.2/")
    arguments = parser.parse_args(argv)
    settings = tuple(arguments.settings.split(","))
    unknown = [setting for setting in settings if setting not in SERVER_SETTINGS]
    if unknown:
        parser.error(f"unknown settings: {unknown}")
    ok, reason = preflight_v12(v12_paths())
    if not ok:
        print(f"preflight failed: {reason}")
        return 1
    for record in run_v12(arguments.repeat, output_dir=arguments.output_dir, settings=settings):
        print(
            f"{record.run_id}: result={record.metrics.handshake_result} "
            f"hrr_pcap={record.metrics.hrr_pcap_present} final={record.metrics.final_negotiated_group} "
            f"precondition={record.metrics.client_precondition_verified}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
