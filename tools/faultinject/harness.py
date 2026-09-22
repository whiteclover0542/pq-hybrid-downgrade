from __future__ import annotations

import re
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from faultinject.record import HYBRID_GROUPS, Metrics, RunRecord, run_id


_GROUP_RE = {
    "openssl": re.compile(
        r"(?:Negotiated TLS1\.3 group:\s*|Peer Temp Key:\s*)(\S+?)(?:,|\s|$)"
    ),
    "boringssl": re.compile(r"ECDHE group:\s*(\S+)"),
    "openssh": re.compile(r"kex: algorithm:\s*(\S+)"),
}

_SUCCESS_MARK = {
    "openssl": lambda text: "Negotiated TLS1.3 group:" in text
    or ("New, TLSv1.3" in text and "DONE" in text),
    "boringssl": lambda text: "Connected." in text and "Version: TLSv1.3" in text,
    "openssh": lambda text: 'using "publickey"' in text,
}


def parse_group(impl: str, client_log_text: str) -> str | None:
    match = _GROUP_RE[impl].search(client_log_text)
    group = match.group(1) if match else None
    return None if group == "<NULL>" else group


def parse_handshake(impl: str, client_log_text: str, exit_code: int) -> str:
    success = exit_code == 0 and _SUCCESS_MARK[impl](client_log_text)
    return "success" if success else "failure"


def collect_metrics(impl: str, client_log_text: str, exit_code: int) -> Metrics:
    group = parse_group(impl, client_log_text)
    is_hybrid = group in HYBRID_GROUPS
    return Metrics(
        negotiated_group=group,
        is_hybrid=is_hybrid,
        downgrade_visible=group is not None and not is_hybrid,
        handshake_result=parse_handshake(impl, client_log_text, exit_code),
    )


def wait_for_listener(
    host: str, port: int, timeout: float = 5, retry_interval: float = 0.05
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            connection = socket.create_connection((host, port), timeout=retry_interval)
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Server did not listen on {host}:{port} within {timeout}s")
            time.sleep(retry_interval)
        else:
            connection.close()
            return


def capture_command(pcap_path: Path, listen_port: int) -> list[str]:
    return [
        "tshark",
        "-i",
        "lo",
        "-l",
        "-f",
        f"tcp port {listen_port}",
        "-a",
        "duration:3",
        "-w",
        str(pcap_path),
    ]


@dataclass
class ScenarioSpec:
    impl: str
    fault_type: str
    repetition: int
    condition: str
    server_cmd: list[str]
    client_cmd: list[str]
    listen_port: int
    env: dict[str, str]
    out_dir: Path
    manipulation_verified: bool = False
    capture_traffic: bool = False
    server_listen_port: int | None = None
    proxy_upstream_port: int | None = None
    proxy_mutate: Callable[[bytes], bytes] | None = None
    proxy_log: Path | None = None


def run_scenario(spec: ScenarioSpec) -> RunRecord:
    identifier = run_id(spec.impl, spec.fault_type, spec.repetition, spec.condition)
    spec.out_dir.mkdir(parents=True, exist_ok=True)
    client_log = spec.out_dir / f"{identifier}-client.log"
    server_log = spec.out_dir / f"{identifier}-server.log"
    pcap_path = spec.out_dir / f"{identifier}.pcapng"
    capture_log = spec.out_dir / f"{identifier}-capture.log"
    capture = None
    proxy_thread = None
    proxy_errors: list[BaseException] = []

    with server_log.open("w", encoding="utf-8") as server_output, capture_log.open(
        "w", encoding="utf-8"
    ) as capture_output:
        server = subprocess.Popen(
            spec.server_cmd,
            env=spec.env,
            stdout=server_output,
            stderr=subprocess.STDOUT,
        )
        try:
            server_port = spec.server_listen_port or spec.listen_port
            if spec.capture_traffic:
                capture = subprocess.Popen(
                    capture_command(pcap_path, server_port),
                    stdout=capture_output,
                    stderr=subprocess.STDOUT,
                )
                deadline = time.monotonic() + 5
                while not pcap_path.exists():
                    if capture.poll() is not None:
                        raise RuntimeError("tshark exited before the capture began")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("tshark did not create a capture file within 5s")
                    time.sleep(0.05)
            wait_for_listener("127.0.0.1", server_port)
            if capture is not None:
                if capture.poll() is not None:
                    raise RuntimeError("tshark exited before the capture stabilized")
                time.sleep(1)
            if spec.proxy_upstream_port is not None and spec.proxy_mutate is not None:
                from faultinject.mitm_proxy import run_proxy

                proxy_ready = threading.Event()

                def start_proxy() -> None:
                    try:
                        run_proxy(
                            spec.listen_port,
                            spec.proxy_upstream_port,
                            spec.proxy_mutate,
                            proxy_ready,
                        )
                    except BaseException as error:
                        proxy_errors.append(error)

                proxy_thread = threading.Thread(target=start_proxy)
                proxy_thread.start()
                if not proxy_ready.wait(timeout=5):
                    raise TimeoutError("proxy did not begin listening within 5s")
            client = subprocess.run(
                spec.client_cmd,
                env=spec.env,
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            server.terminate()
            server.wait(timeout=5)
            if capture is not None:
                try:
                    capture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture.send_signal(signal.SIGINT)
                    capture.wait(timeout=5)
            if proxy_thread is not None:
                proxy_thread.join(timeout=5)

    if proxy_errors:
        raise RuntimeError("proxy failed") from proxy_errors[0]

    client_text = client.stdout + client.stderr
    client_log.write_text(client_text, encoding="utf-8")
    record = RunRecord(
        run_id=identifier,
        implementation=spec.impl,
        fault_type=spec.fault_type,
        repetition=spec.repetition,
        condition=spec.condition,
        metrics=collect_metrics(spec.impl, client_text, client.returncode),
        manipulation_verified=spec.manipulation_verified,
        artifacts={
            "client_log": client_log.name,
            "server_log": server_log.name,
            **({"pcap": pcap_path.name, "capture_log": capture_log.name} if capture else {}),
            **({"proxy_log": spec.proxy_log.name} if spec.proxy_log else {}),
        },
    )
    record.to_json_path(spec.out_dir)
    return record
