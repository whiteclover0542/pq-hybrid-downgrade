from __future__ import annotations

from pathlib import Path

from faultinject.harness import ScenarioSpec


_CLASSICAL = {
    "openssl": ("-groups", "X25519:P-256"),
    "boringssl": ("-curves", "X25519:P-256"),
    "openssh": ("-o", "KexAlgorithms=curve25519-sha256"),
}


def group_list_spec(
    impl: str,
    rep: int,
    env: dict[str, str],
    out_dir: Path,
    paths: dict[str, str | list[str]],
) -> ScenarioSpec:
    flag, value = _CLASSICAL[impl]

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
            "8443",
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
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-connect",
            "127.0.0.1:8443",
            flag,
            value,
        ]
    elif impl == "boringssl":
        bssl_bin = str(paths["bssl_bin"])
        server_cmd = [
            bssl_bin,
            "server",
            "-accept",
            "8444",
            "-curves",
            "X25519Kyber768Draft00:X25519",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
        ]
        client_cmd = [
            bssl_bin,
            "client",
            "-connect",
            "127.0.0.1:8444",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
            flag,
            value,
        ]
    elif impl == "openssh":
        server_cmd = list(paths["sshd_cmd"])
        client_cmd = [
            str(paths["ssh_bin"]),
            "-vvv",
            flag,
            value,
            "-p",
            "2222",
            "root@127.0.0.1",
            "true",
        ]
    else:
        raise ValueError(f"Unsupported implementation: {impl}")

    return ScenarioSpec(
        impl=impl,
        fault_type="group-list",
        repetition=rep,
        condition="default",
        server_cmd=server_cmd,
        client_cmd=client_cmd,
        env=env,
        out_dir=out_dir,
    )
