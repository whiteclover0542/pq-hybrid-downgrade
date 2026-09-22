from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from faultinject.record import HYBRID_GROUPS, Metrics, RunRecord, run_id


_GROUP_RE = {
    "openssl": re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)"),
    "boringssl": re.compile(r"ECDHE group:\s*(\S+)"),
    "openssh": re.compile(r"kex: algorithm:\s*(\S+)"),
}

_SUCCESS_MARK = {
    "openssl": lambda text: "Negotiated TLS1.3 group:" in text,
    "boringssl": lambda text: "Connected." in text and "Version: TLSv1.3" in text,
    "openssh": lambda text: 'using "publickey"' in text,
}


def parse_group(impl: str, client_log_text: str) -> str | None:
    match = _GROUP_RE[impl].search(client_log_text)
    return match.group(1) if match else None


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


@dataclass
class ScenarioSpec:
    impl: str
    fault_type: str
    repetition: int
    condition: str
    server_cmd: list[str]
    client_cmd: list[str]
    env: dict[str, str]
    out_dir: Path
    manipulation_verified: bool = True


def run_scenario(spec: ScenarioSpec) -> RunRecord:
    identifier = run_id(spec.impl, spec.fault_type, spec.repetition, spec.condition)
    spec.out_dir.mkdir(parents=True, exist_ok=True)
    client_log = spec.out_dir / f"{identifier}-client.log"
    server_log = spec.out_dir / f"{identifier}-server.log"

    with server_log.open("w", encoding="utf-8") as server_output:
        server = subprocess.Popen(
            spec.server_cmd,
            env=spec.env,
            stdout=server_output,
            stderr=subprocess.STDOUT,
        )
        try:
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
        artifacts={"client_log": client_log.name, "server_log": server_log.name},
    )
    record.to_json_path(spec.out_dir)
    return record
