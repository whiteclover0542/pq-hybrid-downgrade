from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.conditions import advertised_hybrid_for, condition_spec
from faultinject.fault_binding import binding_spec
from faultinject.fault_group_list import group_list_spec
from faultinject.harness import ScenarioSpec, run_scenario
from faultinject.record import RunRecord
from faultinject.ssh_kexinit import strip_kexinit_algorithm
from faultinject.tls_clienthello import strip_hybrid
from faultinject.verify_applied import (
    mark,
    verify_binding,
    verify_group_list,
    verify_ssh_group_list,
)


PHASE2_ROOT = "/root/pq-hybrid-phase2"


def default_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/phase-3"


def phase4_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/phase-4"


def v11_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.1"


def phase2_paths() -> dict[str, str]:
    return {
        "openssl_bin": f"{PHASE2_ROOT}/install/openssl/bin/openssl",
        "openssl_cert": f"{PHASE2_ROOT}/openssl/apps/server.pem",
        "bssl_bin": f"{PHASE2_ROOT}/build/boringssl/tool/bssl",
        "boring_cert": f"{PHASE2_ROOT}/boring-cert.pem",
        "boring_key": f"{PHASE2_ROOT}/boring-key.pem",
        "ssh_bin": f"{PHASE2_ROOT}/openssh/ssh",
        "sshd_bin": f"{PHASE2_ROOT}/openssh/sshd",
        "sshd_config": f"{PHASE2_ROOT}/openssh-run/sshd_config",
        "ssh_key": f"{PHASE2_ROOT}/openssh-run/client_ed25519",
    }


def phase2_environment() -> dict[str, str]:
    environment = os.environ.copy()
    openssl_lib = f"{PHASE2_ROOT}/install/openssl/lib64"
    liboqs_lib = f"{PHASE2_ROOT}/install/liboqs/lib"
    existing = environment.get("LD_LIBRARY_PATH", "")
    environment["LD_LIBRARY_PATH"] = ":".join(
        value for value in (openssl_lib, liboqs_lib, existing) if value
    )
    environment["OPENSSL_MODULES"] = f"{openssl_lib}/ossl-modules"
    return environment


def preflight(paths: dict, environment: dict, runner=subprocess.run) -> tuple[bool, str]:
    for key in ("openssl_bin", "bssl_bin", "ssh_bin", "sshd_bin"):
        if not Path(paths[key]).exists():
            return False, f"missing binary: {key} -> {paths[key]}"
    result = runner(
        [paths["openssl_bin"], "list", "-providers",
         "-provider", "default", "-provider", "oqsprovider"],
        env=environment, capture_output=True, text=True,
    )
    if "oqsprovider" not in result.stdout:
        return False, "oqsprovider not loaded — check LD_LIBRARY_PATH/OPENSSL_MODULES"
    return True, "ok"


def smoke_specs(output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or default_output_dir()
    paths = phase2_paths()
    environment = phase2_environment()
    implementations = ("openssl", "boringssl", "openssh")
    return [
        *[
            group_list_spec(impl, 1, environment, out_dir, paths)
            for impl in implementations
        ],
        *[binding_spec(impl, 1, environment, out_dir, paths) for impl in implementations],
    ]


def batch_specs(repetitions: int, output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or phase4_output_dir()
    paths = phase2_paths()
    environment = phase2_environment()
    implementations = ("openssl", "boringssl", "openssh")
    specs: list[ScenarioSpec] = []
    for rep in range(1, repetitions + 1):
        for impl in implementations:
            specs.append(group_list_spec(impl, rep, environment, out_dir, paths))
            specs.append(binding_spec(impl, rep, environment, out_dir, paths))
    return specs


def _strip_spec(
    impl: str, repetition: int, environment: dict[str, str], out_dir: Path, paths: dict[str, str]
) -> ScenarioSpec:
    base = condition_spec(impl, "base", repetition, environment, out_dir, paths)
    proxy_port = {"openssl": 9543, "boringssl": 9544, "openssh": 9555}[impl]
    group_id = {
        "openssl": 0x11EC,
        "boringssl": 0x6399,
        "openssh": "sntrup761x25519-sha512@openssh.com",
    }[impl]
    proxy_log = out_dir / f"{impl}_condition_r{repetition:02d}_onpath-strip-proxy.log"
    client_cmd = [
        (
            f"127.0.0.1:{proxy_port}"
            if value == f"127.0.0.1:{base.listen_port}"
            else str(proxy_port) if value == str(base.listen_port) else value
        )
        for value in base.client_cmd
    ]

    def mutate(data: bytes) -> bytes:
        try:
            stripped = (
                strip_kexinit_algorithm(data, group_id)
                if impl == "openssh"
                else strip_hybrid(data, group_id)
            )
        except ValueError:
            return data
        if stripped != data:
            with proxy_log.open("a", encoding="utf-8") as output:
                output.write(
                    "event=strip_mutation "
                    f"group_id={group_id if isinstance(group_id, str) else f'0x{group_id:04x}'} "
                    f"before_sha256={hashlib.sha256(data).hexdigest()} "
                    f"after_sha256={hashlib.sha256(stripped).hexdigest()}\n"
                )
        return stripped

    return replace(
        base,
        condition="onpath-strip",
        client_cmd=client_cmd,
        listen_port=proxy_port,
        server_listen_port=base.listen_port,
        proxy_upstream_port=base.listen_port,
        proxy_mutate=mutate,
        proxy_log=proxy_log,
        advertised_hybrid=True,
    )


def v11_specs(repetitions: int, output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or v11_output_dir()
    paths = phase2_paths()
    environment = phase2_environment()
    specs: list[ScenarioSpec] = []
    for repetition in range(1, repetitions + 1):
        for impl in ("openssl", "boringssl"):
            for condition in ("base", "silent-downgrade"):
                spec = condition_spec(impl, condition, repetition, environment, out_dir, paths)
                specs.append(replace(spec, advertised_hybrid=advertised_hybrid_for(condition)))
            specs.append(_strip_spec(impl, repetition, environment, out_dir, paths))
        for condition in ("base", "ssh-order"):
            spec = condition_spec("openssh", condition, repetition, environment, out_dir, paths)
            specs.append(replace(spec, advertised_hybrid=advertised_hybrid_for(condition)))
        specs.append(_strip_spec("openssh", repetition, environment, out_dir, paths))
    return specs


def _baseline_path(implementation: str) -> Path:
    root = Path(__file__).resolve().parents[2] / "docs/research/baselines/raw"
    names = {
        "openssl": "openssl-67b5686b-baseline",
        "boringssl": "boringssl-7fb4d3da-baseline",
        "openssh": "openssh-d01efaa1-baseline",
    }
    return root / names[implementation]


def verify_record(record: RunRecord, output_dir: Path) -> RunRecord:
    if record.fault_type == "binding":
        verified = verify_binding(output_dir / record.artifacts["proxy_log"])
    elif record.implementation == "openssh":
        baseline = _baseline_path("openssh")
        verified = verify_ssh_group_list(
            output_dir / record.artifacts["client_log"], baseline.with_name(baseline.name + "-client.log")
        )
    else:
        baseline = _baseline_path(record.implementation)
        verified = verify_group_list(
            output_dir / record.artifacts["pcap"], baseline.with_name(baseline.name + ".pcapng")
        )
    marked = mark(record, verified)
    marked.to_json_path(output_dir)
    return marked


def run_smoke(output_dir: Path | None = None) -> list[RunRecord]:
    out_dir = output_dir or default_output_dir()
    return [verify_record(run_scenario(spec), out_dir) for spec in smoke_specs(out_dir)]


def run_batch(repetitions: int, output_dir: Path | None = None) -> list[RunRecord]:
    out_dir = output_dir or phase4_output_dir()
    return [verify_record(run_scenario(spec), out_dir) for spec in batch_specs(repetitions, out_dir)]


def run_v11(repetitions: int, output_dir: Path | None = None) -> list[RunRecord]:
    out_dir = output_dir or v11_output_dir()
    return [verify_record(run_scenario(spec), out_dir) for spec in v11_specs(repetitions, out_dir)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Phase 3 loopback fault-injection smoke tests")
    parser.add_argument("--smoke", action="store_true", help="run all six Phase 3 scenarios once")
    parser.add_argument("--repeat", type=int, metavar="N",
                        help="run each of the six combinations N times into raw/phase-4/")
    parser.add_argument("--v11", type=int, metavar="N",
                        help="run each v1.1 condition combination N times into raw/v1.1/")
    arguments = parser.parse_args(argv)
    if arguments.repeat:
        ok, reason = preflight(phase2_paths(), phase2_environment())
        if not ok:
            print(f"preflight failed: {reason}")
            return 1
        for record in run_batch(arguments.repeat):
            print(f"{record.run_id}: result={record.metrics.handshake_result} "
                  f"verified={record.manipulation_verified}")
        return 0
    if arguments.v11:
        ok, reason = preflight(phase2_paths(), phase2_environment())
        if not ok:
            print(f"preflight failed: {reason}")
            return 1
        for record in run_v11(arguments.v11):
            print(f"{record.run_id}: result={record.metrics.handshake_result} "
                  f"verified={record.manipulation_verified}")
        return 0
    if not arguments.smoke:
        parser.print_help()
        return 0
    for record in run_smoke():
        print(
            f"{record.run_id}: result={record.metrics.handshake_result} "
            f"verified={record.manipulation_verified}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
