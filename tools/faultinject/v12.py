from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

from faultinject.harness import ScenarioSpec

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
