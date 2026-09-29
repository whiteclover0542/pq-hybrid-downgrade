"""v1.5: compare the negotiation function of five TLS 1.3 server implementations.

No manipulation: a fixed OpenSSL 3.5.5 client connects to each server configured with the
hybrid group listed first, and the pcap records whether the server sent an HRR and which group
it selected. Three client configurations vary the advertised order and the key share sent.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.harness import ScenarioSpec, run_scenario
from faultinject.pcap_hello import group_name, summarize_hellos
from faultinject.record import RunRecord
from faultinject.v12 import PHASE2_ROOT, V12_PORT, _port_free, native_environment, sha256_file

PORT = V12_PORT
PEM = f"{PHASE2_ROOT}/openssl/apps/server.pem"
V15 = f"{PHASE2_ROOT}/v15"
OPENSSL_SERVER = f"{PHASE2_ROOT}/install/openssl-3.5.6/bin/openssl"
CLIENT_BIN = f"{PHASE2_ROOT}/install/openssl/bin/openssl"
BSSL = f"{PHASE2_ROOT}/build/boringssl/tool/bssl"

# client label -> (-groups argument, expected supported_groups order, expected key shares)
CLIENTS = {
    "C1": ("X25519MLKEM768:X25519", [0x11EC, 0x001D], [0x11EC]),
    "C2": ("X25519MLKEM768:*X25519", [0x11EC, 0x001D], [0x001D]),
    "C3": ("X25519:X25519MLKEM768", [0x001D, 0x11EC], [0x001D]),
}

_OPENSSL = [OPENSSL_SERVER, "s_server", "-tls1_3", "-www", "-provider", "default", "-accept", str(PORT), "-cert", PEM]
SERVERS = {
    "openssl-S1": [*_OPENSSL, "-groups", "X25519MLKEM768:X25519"],
    "openssl-S2": [*_OPENSSL, "-groups", "X25519MLKEM768/X25519"],
    "openssl-S1-serverpref": [*_OPENSSL, "-groups", "X25519MLKEM768:X25519", "-serverpref"],
    "boringssl": [BSSL, "server", "-accept", str(PORT), "-key", PEM, "-min-version", "tls1.3",
                  "-max-version", "tls1.3", "-curves", "X25519MLKEM768:X25519", "-loop"],
    "go": [f"{V15}/goserver", "-addr", f"127.0.0.1:{PORT}", "-pem", PEM, "-groups", "X25519MLKEM768,X25519"],
    "nss": ["selfserv", "-d", f"sql:{V15}/nssdb", "-n", "server", "-p", str(PORT), "-V", "tls1.3:tls1.3",
            "-I", "x25519mlkem768,x25519"],
    "rustls": [f"{V15}/rustserver", str(PORT), PEM, "X25519MLKEM768,X25519"],
}


def v15_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.5"


def server_command(server: str) -> list[str]:
    return SERVERS[server]


def _server_env(server: str) -> dict[str, str]:
    if server.startswith("openssl"):
        return native_environment("3.5.6")
    return {key: value for key, value in os.environ.items() if key not in ("LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES")}


def v15_spec(server: str, client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    client_cmd = [CLIENT_BIN, "s_client", "-tls1_3", "-state", "-msg", "-provider", "default",
                  "-connect", f"127.0.0.1:{PORT}", "-groups", CLIENTS[client][0]]
    return ScenarioSpec(
        impl="openssl", fault_type="negotiation-function", repetition=repetition,
        condition=f"{server}-{client}", server_cmd=SERVERS[server], client_cmd=client_cmd,
        listen_port=PORT, env=native_environment("3.5.5"), out_dir=out_dir,
        capture_traffic=True, advertised_hybrid=True, server_env=_server_env(server),
    )


def v15_specs(repetitions: int, output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or v15_output_dir()
    return [v15_spec(server, client, rep, out_dir)
            for rep in range(1, repetitions + 1) for server in SERVERS for client in CLIENTS]


def client_precondition_v15(summary, client: str) -> bool:
    if not summary.client_hellos:
        return False
    groups, shares = summary.client_hellos[0]
    _, expected_groups, expected_shares = CLIENTS[client]
    return groups == expected_groups and shares == expected_shares


def evaluate_v15(record: RunRecord, run_dir: Path, server: str, client: str) -> RunRecord:
    metrics = replace(record.metrics)
    pcap = Path(run_dir) / record.artifacts.get("pcap", "")
    if pcap.is_file() and pcap.stat().st_size > 0:
        summary = summarize_hellos(pcap.read_bytes())
        metrics.hrr_pcap_present = summary.hrr_count > 0
        metrics.server_hello_count = summary.server_hello_count
        metrics.final_negotiated_group = group_name(summary.final_group)
        metrics.client_precondition_verified = client_precondition_v15(summary, client)
    else:
        metrics.client_precondition_verified = False
    metrics.downgrade_flagged = None
    # the client prints "New, TLSv1.3" once the handshake is complete; a later alert (e.g. at close) can still
    # make the exit status non-zero, so key-exchange completion is recorded separately from handshake_result
    client_log = Path(run_dir) / record.artifacts.get("client_log", "")
    completed = client_log.is_file() and "New, TLSv1.3" in client_log.read_text(encoding="utf-8", errors="replace")
    metrics.detail = "handshake-completed" if completed else "handshake-incomplete"
    evaluated = replace(
        record, metrics=metrics, manipulation_verified=metrics.client_precondition_verified is True,
        provenance={"server": server, "client": client, "server_cmd": SERVERS[server],
                    "client_groups_arg": CLIENTS[client][0],
                    "server_bin_sha256": sha256_file(Path(SERVERS[server][0]))},
    )
    evaluated.to_json_path(run_dir)
    return evaluated


def run_v15(repetitions: int, output_dir: Path | None = None, scenario_runner=run_scenario) -> list[RunRecord]:
    out_dir = Path(output_dir or v15_output_dir())
    if out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    records = []
    for spec in v15_specs(repetitions, out_dir):
        server, client = spec.condition.rsplit("-", 1)
        records.append(evaluate_v15(scenario_runner(spec), out_dir, server, client))
    return records


def comparison_v15(run_dir) -> dict:
    out: dict = {}
    for path in sorted(Path(run_dir).glob("*.json")):
        record = RunRecord.from_json(path)
        if record.fault_type != "negotiation-function":
            continue
        key = (record.provenance["server"], record.provenance["client"])
        count = out.setdefault(key, {"n": 0, "precondition": 0, "completed": 0, "success": 0, "hrr": 0,
                                     "hybrid": 0, "classical": 0, "unknown": 0})
        metrics = record.metrics
        final = metrics.final_negotiated_group
        count["n"] += 1
        count["precondition"] += int(metrics.client_precondition_verified is True)
        count["completed"] += int(metrics.detail == "handshake-completed")
        count["success"] += int(metrics.handshake_result == "success")
        count["hrr"] += int(metrics.hrr_pcap_present is True)
        count["hybrid" if final == "X25519MLKEM768" else "classical" if final == "X25519" else "unknown"] += 1
    return out


def render_v15(run_dir) -> str:
    lines = ["| server | client | precondition/n | handshake completed | clean exit | HRR (PCAP) | hybrid | classical | unknown |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    order = {name: index for index, name in enumerate(SERVERS)}
    for (server, client), c in sorted(comparison_v15(run_dir).items(), key=lambda item: (order.get(item[0][0], 99), item[0][1])):
        lines.append(f"| {server} | {client} | {c['precondition']}/{c['n']} | {c['completed']} | {c['success']} | {c['hrr']} | "
                     f"{c['hybrid']} | {c['classical']} | {c['unknown']} |")
    return "\n".join(lines)


def preflight_v15() -> tuple[bool, str]:
    for server, command in SERVERS.items():
        binary = command[0]
        if "/" in binary and not Path(binary).exists():
            return False, f"missing server binary for {server}: {binary}"
    for path in (CLIENT_BIN, PEM, f"{V15}/nssdb"):
        if not Path(path).exists():
            return False, f"missing: {path}"
    if not _port_free(PORT):
        return False, f"port {PORT} in use"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare TLS 1.3 server negotiation functions (v1.5)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repeat", type=int, metavar="N", help="repetitions per server x client combination")
    mode.add_argument("--report", type=Path, metavar="DIR", help="print the comparison table for DIR")
    parser.add_argument("--output-dir", type=Path, metavar="PATH")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(render_v15(arguments.report))
        return 0
    ok, reason = preflight_v15()
    if not ok:
        print(f"preflight failed: {reason}")
        return 1
    for record in run_v15(arguments.repeat, arguments.output_dir):
        print(f"{record.run_id}: result={record.metrics.handshake_result} hrr={record.metrics.hrr_pcap_present} "
              f"final={record.metrics.final_negotiated_group} precondition={record.metrics.client_precondition_verified}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
