from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

from faultinject.harness import ScenarioSpec
from faultinject.record import run_id
from faultinject.ssh_kexinit import forge_ssh_pq_component
from faultinject.tls_clienthello import forge_pq_component


def _logged_mutator(
    path: Path, group_id: str, transform: Callable[[bytes], bytes]
) -> Callable[[bytes], bytes]:
    def mutate(data: bytes) -> bytes:
        try:
            forged = transform(data)
        except ValueError:
            return data
        if forged != data:
            with path.open("a", encoding="utf-8") as output:
                output.write(
                    "event=binding_mutation "
                    f"group_id={group_id} "
                    f"before_sha256={hashlib.sha256(data).hexdigest()} "
                    f"after_sha256={hashlib.sha256(forged).hexdigest()}\n"
                )
        return forged

    return mutate


def binding_spec(
    impl: str,
    rep: int,
    env: dict[str, str],
    out_dir: Path,
    paths: dict[str, str],
) -> ScenarioSpec:
    identifier = run_id(impl, "binding", rep, "default")
    proxy_log = out_dir / f"{identifier}-proxy.log"

    if impl == "openssl":
        server_cmd = [
            paths["openssl_bin"],
            "s_server",
            "-tls1_3",
            "-www",
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-accept",
            "8445",
            "-cert",
            paths["openssl_cert"],
            "-groups",
            "X25519MLKEM768",
        ]
        client_cmd = [
            paths["openssl_bin"],
            "s_client",
            "-tls1_3",
            "-state",
            "-provider",
            "default",
            "-provider",
            "oqsprovider",
            "-connect",
            "127.0.0.1:9443",
            "-groups",
            "X25519MLKEM768",
        ]
        listen_port, upstream_port = 9443, 8445
        group_id = "0x11ec"
        transform = lambda data: forge_pq_component(data, 0x11EC)
    elif impl == "boringssl":
        server_cmd = [
            paths["bssl_bin"],
            "server",
            "-accept",
            "8446",
            "-curves",
            "X25519Kyber768Draft00",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
            "-cert",
            paths["boring_cert"],
            "-key",
            paths["boring_key"],
            "-loop",
        ]
        client_cmd = [
            paths["bssl_bin"],
            "client",
            "-connect",
            "127.0.0.1:9444",
            "-min-version",
            "tls1.3",
            "-max-version",
            "tls1.3",
            "-curves",
            "X25519Kyber768Draft00",
        ]
        listen_port, upstream_port = 9444, 8446
        group_id = "0x6399"
        transform = lambda data: forge_pq_component(data, 0x6399)
    elif impl == "openssh":
        server_cmd = [
            paths["sshd_bin"],
            "-D",
            "-e",
            "-f",
            paths["sshd_config"],
            "-p",
            "2224",
            "-o",
            "PidFile=/tmp/pq-hybrid-phase3-binding-sshd.pid",
        ]
        client_cmd = [
            paths["ssh_bin"],
            "-vvv",
            "-o",
            "KexAlgorithms=sntrup761x25519-sha512@openssh.com",
            "-p",
            "2225",
            "-i",
            paths["ssh_key"],
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "root@127.0.0.1",
            "true",
        ]
        listen_port, upstream_port = 2225, 2224
        group_id = "sntrup761x25519-sha512@openssh.com"
        transform = forge_ssh_pq_component
    else:
        raise ValueError(f"Unsupported implementation: {impl}")

    return ScenarioSpec(
        impl=impl,
        fault_type="binding",
        repetition=rep,
        condition="default",
        server_cmd=server_cmd,
        client_cmd=client_cmd,
        listen_port=listen_port,
        server_listen_port=upstream_port,
        proxy_upstream_port=upstream_port,
        proxy_mutate=_logged_mutator(proxy_log, group_id, transform),
        proxy_log=proxy_log,
        env=env,
        out_dir=out_dir,
        capture_traffic=True,
    )
