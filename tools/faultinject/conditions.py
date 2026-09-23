from __future__ import annotations

from pathlib import Path

from faultinject.harness import ScenarioSpec


# client group order per (impl, condition): base = hybrid-first, silent-downgrade = classical-first
_CLIENT_GROUPS = {
    "openssl": {
        "base": "X25519MLKEM768:X25519",
        "silent-downgrade": "X25519:X25519MLKEM768",
    },
    "boringssl": {
        "base": "X25519Kyber768Draft00:X25519",
        "silent-downgrade": "X25519:X25519Kyber768Draft00",
    },
}

_PORTS = {"openssl": 8543, "boringssl": 8544, "openssh": 2323}

_ADVERTISED_HYBRID = {"base": True, "silent-downgrade": True, "ssh-order": True}


def advertised_hybrid_for(condition: str) -> bool:
    return _ADVERTISED_HYBRID[condition]


def condition_spec(
    impl: str,
    condition: str,
    rep: int,
    env: dict[str, str],
    out_dir: Path,
    paths: dict[str, str | list[str]],
) -> ScenarioSpec:
    port = _PORTS[impl]

    if impl == "openssl":
        openssl_bin = str(paths["openssl_bin"])
        server_cmd = [
            openssl_bin,
            "s_server",
            "-tls1_3",
            "-www",
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-accept",
            str(port),
            "-cert",
            str(paths["openssl_cert"]),
            "-groups",
            "X25519MLKEM768:X25519",
        ]
        client_cmd = [
            openssl_bin,
            "s_client",
            "-tls1_3",
            "-state",
            "-msg",
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-connect",
            f"127.0.0.1:{port}",
            "-groups",
            _CLIENT_GROUPS["openssl"][condition],
        ]
    elif impl == "boringssl":
        bssl_bin = str(paths["bssl_bin"])
        server_cmd = [
            bssl_bin,
            "server",
            "-accept",
            str(port),
            "-curves",
            "X25519Kyber768Draft00:X25519",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
            "-cert",
            str(paths["boring_cert"]),
            "-key",
            str(paths["boring_key"]),
            "-loop",
        ]
        client_cmd = [
            bssl_bin,
            "client",
            "-connect",
            f"127.0.0.1:{port}",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
            "-curves",
            _CLIENT_GROUPS["boringssl"][condition],
        ]
    elif impl == "openssh":
        server_cmd = [
            str(paths["sshd_bin"]),
            "-D",
            "-e",
            "-f",
            str(paths["sshd_config"]),
            "-p",
            str(port),
            "-o",
            "PidFile=/tmp/pq-hybrid-phase3-sshd.pid",
            "-o",
            "KexAlgorithms=sntrup761x25519-sha512@openssh.com,curve25519-sha256",
        ]
        client_cmd = [
            str(paths["ssh_bin"]),
            "-vvv",
            "-o",
            "KexAlgorithms=sntrup761x25519-sha512@openssh.com,curve25519-sha256",
            "-p",
            str(port),
            "-i",
            str(paths["ssh_key"]),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "root@127.0.0.1",
            "true",
        ]
    else:
        raise ValueError(f"Unsupported implementation: {impl}")

    return ScenarioSpec(
        impl=impl,
        fault_type="condition",
        repetition=rep,
        condition=condition,
        server_cmd=server_cmd,
        client_cmd=client_cmd,
        listen_port=port,
        env=env,
        out_dir=out_dir,
        capture_traffic=True,
    )
