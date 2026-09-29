"""v1.6: which key shares do client libraries send by default, and how do real server packages choose?

Part 1 (client survey): each client library connects with its default configuration to an OpenSSL 3.5.6
server; the pcap records the ClientHello's supported_groups and key_share.
Part 2 (server software): nginx and Caddy from the distribution, left at their default group settings,
receive the three fixed OpenSSL clients C1-C3 from v1.5.
No manipulation in either part.
"""
from __future__ import annotations

import argparse
import os
from dataclasses import replace
from pathlib import Path

from faultinject.harness import ScenarioSpec, run_scenario
from faultinject.pcap_hello import group_name, summarize_hellos
from faultinject.record import RunRecord
from faultinject.v12 import PHASE2_ROOT, _port_free, native_environment, sha256_file
from faultinject.v15 import CLIENT_BIN, CLIENTS, OPENSSL_SERVER, PEM, PORT, V15, client_precondition_v15

V16 = f"{PHASE2_ROOT}/v16"
ADDR = f"127.0.0.1:{PORT}"

# client label -> command using that library's default key-exchange configuration
DEFAULT_CLIENTS = {
    "openssl-3.5.5": [CLIENT_BIN, "s_client", "-tls1_3", "-provider", "default", "-connect", ADDR],
    "curl-system-openssl": ["curl", "-sk", "--tlsv1.3", "-o", "/dev/null", f"https://{ADDR}/"],
    "boringssl": [f"{PHASE2_ROOT}/build/boringssl/tool/bssl", "client", "-connect", ADDR, "-min-version", "tls1.3"],
    "go": [f"{V15}/goclient", "-connect", ADDR],
    "nss": ["tstclnt", "-d", f"sql:{V15}/nssdb", "-h", "127.0.0.1", "-p", str(PORT), "-o", "-Q", "-V", "tls1.3:tls1.3"],
    "rustls": [f"{V15}/rustclient", ADDR],
}
SURVEY_SERVER = [OPENSSL_SERVER, "s_server", "-tls1_3", "-www", "-provider", "default", "-accept", str(PORT), "-cert", PEM]

REAL_SERVERS = {
    "nginx": ["nginx", "-c", f"{V16}/nginx.conf", "-g", "daemon off;"],
    # A comparison binary can be supplied without replacing the distro package.
    "caddy": [os.environ.get("FAULTINJECT_V16_CADDY", "caddy"), "run", "--config", f"{V16}/Caddyfile", "--adapter", "caddyfile"],
}


def v16_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.6"


def v16_direct_output_dir() -> Path:
    """Keep the new default-client/default-server matrix separate from v1.6 E9a/E9b."""
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.6-direct"


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES")}
    env.update(XDG_DATA_HOME=f"{V16}/caddy-data", XDG_CONFIG_HOME=f"{V16}/caddy-config")
    return env


def survey_spec(client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    client_env = native_environment("3.5.5") if client == "openssl-3.5.5" else _clean_env()
    return ScenarioSpec(
        impl="openssl", fault_type="client-default", repetition=repetition, condition=client,
        server_cmd=SURVEY_SERVER, client_cmd=DEFAULT_CLIENTS[client], listen_port=PORT,
        env=client_env, out_dir=out_dir, capture_traffic=True, server_env=native_environment("3.5.6"),
    )


def server_spec(server: str, client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    client_cmd = [CLIENT_BIN, "s_client", "-tls1_3", "-state", "-msg", "-provider", "default",
                  "-connect", ADDR, "-groups", CLIENTS[client][0]]
    return ScenarioSpec(
        impl="openssl", fault_type="server-software", repetition=repetition, condition=f"{server}-{client}",
        server_cmd=REAL_SERVERS[server], client_cmd=client_cmd, listen_port=PORT,
        env=native_environment("3.5.5"), out_dir=out_dir, capture_traffic=True, server_env=_clean_env(),
        capture_seconds=10 if server == "caddy" else 3,  # Caddy can take >2 s to start listening
    )


def direct_spec(server: str, client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    """Connect an unconfigured client directly to an unconfigured packaged server."""
    client_env = native_environment("3.5.5") if client == "openssl-3.5.5" else _clean_env()
    return ScenarioSpec(
        impl="openssl", fault_type="default-direct", repetition=repetition,
        condition=f"{server}--{client}", server_cmd=REAL_SERVERS[server],
        client_cmd=DEFAULT_CLIENTS[client], listen_port=PORT, env=client_env,
        out_dir=out_dir, capture_traffic=True, server_env=_clean_env(),
        capture_seconds=10 if server == "caddy" else 3,
    )


def v16_specs(repetitions: int, output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or v16_output_dir()
    return [
        *[survey_spec(client, rep, out_dir) for rep in range(1, repetitions + 1) for client in DEFAULT_CLIENTS],
        *[server_spec(server, client, rep, out_dir)
          for rep in range(1, repetitions + 1) for server in REAL_SERVERS for client in CLIENTS],
    ]


def v16_direct_specs(repetitions: int, output_dir: Path | None = None) -> list[ScenarioSpec]:
    out_dir = output_dir or v16_direct_output_dir()
    return [
        direct_spec(server, client, rep, out_dir)
        for rep in range(1, repetitions + 1)
        for server in REAL_SERVERS
        for client in DEFAULT_CLIENTS
    ]


def evaluate_v16(record: RunRecord, run_dir: Path, spec: ScenarioSpec) -> RunRecord:
    metrics = replace(record.metrics)
    pcap = Path(run_dir) / record.artifacts.get("pcap", "")
    summary = summarize_hellos(pcap.read_bytes()) if pcap.is_file() else None
    groups, shares = summary.client_hellos[0] if summary and summary.client_hellos else ([], [])
    if summary:
        metrics.hrr_pcap_present = summary.hrr_count > 0
        metrics.server_hello_count = summary.server_hello_count
        metrics.final_negotiated_group = group_name(summary.final_group)
    provenance = {
        "part": (
            "client-survey" if spec.fault_type == "client-default"
            else "default-direct" if spec.fault_type == "default-direct"
            else "server-software"
        ),
        "client_hello_groups": [group_name(g) for g in groups],
        "client_hello_key_shares": [group_name(g) for g in shares],
        "server_cmd": spec.server_cmd, "client_cmd": spec.client_cmd,
        "binary_sha256": sha256_file(Path(spec.client_cmd[0] if spec.fault_type in ("client-default", "default-direct") else spec.server_cmd[0])),
    }
    if spec.fault_type == "server-software":
        server, client = spec.condition.rsplit("-", 1)
        provenance.update(server=server, client=client)
        metrics.client_precondition_verified = client_precondition_v15(summary, client) if summary else False
    elif spec.fault_type == "default-direct":
        server, client = spec.condition.split("--", 1)
        provenance.update(server=server, client=client)
        metrics.client_precondition_verified = bool(groups)
    else:
        provenance.update(client=spec.condition)
        metrics.client_precondition_verified = bool(groups)
    metrics.downgrade_flagged = None
    evaluated = replace(record, metrics=metrics, manipulation_verified=metrics.client_precondition_verified is True,
                        provenance=provenance)
    evaluated.to_json_path(run_dir)
    return evaluated


def run_v16(repetitions: int, output_dir: Path | None = None, scenario_runner=run_scenario) -> list[RunRecord]:
    out_dir = Path(output_dir or v16_output_dir())
    if out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    return [evaluate_v16(scenario_runner(spec), out_dir, spec) for spec in v16_specs(repetitions, out_dir)]


def run_v16_direct(repetitions: int, output_dir: Path | None = None, scenario_runner=run_scenario) -> list[RunRecord]:
    out_dir = Path(output_dir or v16_direct_output_dir())
    if out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    return [evaluate_v16(scenario_runner(spec), out_dir, spec) for spec in v16_direct_specs(repetitions, out_dir)]


def _records(run_dir):
    return [RunRecord.from_json(path) for path in sorted(Path(run_dir).glob("*.json"))]


def render_v16(run_dir) -> str:
    survey: dict = {}
    servers: dict = {}
    direct: dict = {}
    for record in _records(run_dir):
        p, m = record.provenance, record.metrics
        if p.get("part") == "client-survey":
            key = (p["client"], ",".join(p["client_hello_groups"]), ",".join(p["client_hello_key_shares"]))
            survey[key] = survey.get(key, 0) + 1
        elif p.get("part") == "server-software":
            c = servers.setdefault((p["server"], p["client"]), {"n": 0, "pre": 0, "hrr": 0, "hybrid": 0, "classical": 0, "other": 0})
            c["n"] += 1
            c["pre"] += int(m.client_precondition_verified is True)
            c["hrr"] += int(m.hrr_pcap_present is True)
            final = m.final_negotiated_group
            c["hybrid" if final == "X25519MLKEM768" else "classical" if final == "X25519" else "other"] += 1
        elif p.get("part") == "default-direct":
            c = direct.setdefault((p["server"], p["client"]), {"n": 0, "pre": 0, "hrr": 0, "hybrid": 0, "classical": 0, "other": 0})
            c["n"] += 1
            c["pre"] += int(m.client_precondition_verified is True)
            c["hrr"] += int(m.hrr_pcap_present is True)
            final = m.final_negotiated_group
            c["hybrid" if final == "X25519MLKEM768" else "classical" if final == "X25519" else "other"] += 1
    lines = ["| client (default config) | supported_groups (order) | key_share | runs |", "|---|---|---|---:|"]
    lines += [f"| {c} | {g or '-'} | {k or '-'} | {n} |" for (c, g, k), n in sorted(survey.items())]
    lines += ["", "| server (default config) | client | precondition/n | HRR (PCAP) | hybrid | classical | other |",
              "|---|---|---|---:|---:|---:|---:|"]
    lines += [f"| {s} | {c} | {v['pre']}/{v['n']} | {v['hrr']} | {v['hybrid']} | {v['classical']} | {v['other']} |"
              for (s, c), v in sorted(servers.items())]
    lines += ["", "| server (default config) | client (default config) | precondition/n | HRR (PCAP) | hybrid | classical | other |",
              "|---|---|---:|---:|---:|---:|---:|"]
    lines += [f"| {s} | {c} | {v['pre']}/{v['n']} | {v['hrr']} | {v['hybrid']} | {v['classical']} | {v['other']} |"
              for (s, c), v in sorted(direct.items())]
    return "\n".join(lines)


def preflight_v16() -> tuple[bool, str]:
    for command in [*DEFAULT_CLIENTS.values(), *REAL_SERVERS.values(), SURVEY_SERVER]:
        binary = command[0]
        if "/" in binary and not Path(binary).exists():
            return False, f"missing: {binary}"
    for path in (f"{V16}/nginx.conf", f"{V16}/Caddyfile"):
        if not Path(path).exists():
            return False, f"missing: {path}"
    if not _port_free(PORT):
        return False, f"port {PORT} in use"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="v1.6 client default survey and server software comparison")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repeat", type=int, metavar="N")
    mode.add_argument("--direct-repeat", type=int, metavar="N",
                      help="run default clients directly against default nginx/Caddy")
    mode.add_argument("--report", type=Path, metavar="DIR")
    parser.add_argument("--output-dir", type=Path, metavar="PATH")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(render_v16(arguments.report))
        return 0
    ok, reason = preflight_v16()
    if not ok:
        print(f"preflight failed: {reason}")
        return 1
    runner = run_v16_direct if arguments.direct_repeat else run_v16
    repetitions = arguments.direct_repeat or arguments.repeat
    for record in runner(repetitions, arguments.output_dir):
        print(f"{record.run_id}: groups={record.provenance['client_hello_groups']} "
              f"shares={record.provenance['client_hello_key_shares']} hrr={record.metrics.hrr_pcap_present} "
              f"final={record.metrics.final_negotiated_group}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
