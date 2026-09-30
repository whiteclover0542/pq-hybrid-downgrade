"""v1.8: survey additional real TLS clients for a C2-shaped default ClientHello.

Every candidate connects, without a group override, to the native OpenSSL 3.5.6 default
server from v1.6.  PCAP is the source for supported_groups and key_share.  A client is C2
only when it advertises a hybrid group but its first ClientHello has no hybrid key share.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.harness import ScenarioSpec, run_scenario
from faultinject.pcap_hello import group_name, summarize_hellos
from faultinject.record import RunRecord
from faultinject.v12 import PHASE2_ROOT, _port_free, native_environment, sha256_file
from faultinject.v15 import PORT, SERVERS, _server_env
from faultinject.v16 import SURVEY_SERVER, _clean_env

V18 = f"{PHASE2_ROOT}/v18"
ADDR = "127.0.0.1"
_HYBRID_MARKERS = ("MLKEM", "KYBER")

# These commands intentionally leave each implementation's group/key-share policy untouched.
CANDIDATES = {
    "gnutls": {
        "command": ["timeout", "20", "gnutls-cli", "--insecure", "--priority",
                    "NORMAL:-VERS-ALL:+VERS-TLS1.3", "-p", str(PORT), ADDR],
        "binary": "/usr/bin/gnutls-cli", "version": ["gnutls-cli", "--version"], "kind": "independent",
    },
    "botan": {
        "command": ["timeout", "20", "botan", "tls_client", ADDR, f"--port={PORT}",
                    "--ignore-cert-error", "--tls-version=tls1.3"],
        "binary": "/usr/bin/botan", "version": ["botan", "version"], "kind": "independent",
    },
    "wolfssl": {
        "command": [f"{V18}/wolfssl_client", ADDR, str(PORT)],
        "binary": f"{V18}/wolfssl_client", "version": [f"{V18}/wolfssl_client", "--version"], "kind": "independent",
    },
    "mbedtls": {
        "command": [f"{V18}/mbedtls_client", ADDR, str(PORT)],
        "binary": f"{V18}/mbedtls_client", "version": [f"{V18}/mbedtls_client", "--version"], "kind": "independent",
    },
    "s2n-tls": {
        "command": [f"{V18}/s2n-tls/build-awslc/bin/s2nc", "-i", ADDR, str(PORT)],
        "binary": f"{V18}/s2n-tls/build-awslc/bin/s2nc",
        "version": [f"{V18}/s2n-tls/build-awslc/bin/s2nc", "--help"], "kind": "independent",
    },
    "java": {
        "command": ["java", "-cp", V18, "JavaTlsClient", ADDR, str(PORT)],
        "binary": "/usr/bin/java", "version": ["java", "-version"], "kind": "independent",
    },
    "node-openssl": {
        "command": ["node", f"{V18}/node_tls_client.js", ADDR, str(PORT)],
        "binary": "/usr/bin/node", "version": ["node", "--version"], "kind": "openssl-control",
    },
    "python-openssl": {
        "command": ["python3", f"{V18}/python_tls_client.py", ADDR, str(PORT)],
        "binary": "/usr/bin/python3", "version": ["python3", "--version"], "kind": "openssl-control",
    },
}
E8_SERVERS = ("openssl-S1", "openssl-S1-serverpref", "nss", "boringssl", "go")
E8_CLIENTS = ("botan",)
SERVER_SELECTION_TYPES = {
    "openssl-3.5.6-default": "server-order",
    "openssl-S1": "key-share-priority",
    "openssl-S1-serverpref": "key-share-priority",
    "nss": "key-share-priority",
    "boringssl": "client-order",
    "go": "server-order",
}


def v18_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.8"


def _is_hybrid(name: str | None) -> bool:
    return bool(name and any(marker in name.upper() for marker in _HYBRID_MARKERS))


def classify(groups: list[str], shares: list[str]) -> str:
    """Classify the first ClientHello; C2 and C3 differ by advertised first group."""
    advertised = any(_is_hybrid(group) for group in groups)
    sent = any(_is_hybrid(share) for share in shares)
    if not groups:
        return "unparsed"
    if not advertised:
        return "no-hybrid-advertisement"
    if sent:
        return "C1-hybrid-first-share" if _is_hybrid(groups[0]) else "hybrid-share-noncanonical-order"
    return "C2-hybrid-first-share-omitted" if _is_hybrid(groups[0]) else "C3-classical-first-share"


def survey_spec(client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    candidate = CANDIDATES[client]
    return ScenarioSpec(
        impl="openssl", fault_type="client-default-v18", repetition=repetition, condition=client,
        server_cmd=SURVEY_SERVER, client_cmd=candidate["command"], listen_port=PORT, env=_clean_env(),
        out_dir=out_dir, capture_traffic=True, server_env=native_environment("3.5.6"),
    )


def e8_spec(server: str, client: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    """Connect an observed default C3 client to the established server-policy controls."""
    return ScenarioSpec(
        impl="openssl", fault_type="actual-client-e8", repetition=repetition,
        condition=f"{server}--{client}", server_cmd=SERVERS[server], client_cmd=CANDIDATES[client]["command"],
        listen_port=PORT, env=_clean_env(), out_dir=out_dir, capture_traffic=True, server_env=_server_env(server),
    )


def _version(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    return (result.stdout + result.stderr).strip()


def inventory() -> dict:
    rows = {}
    for name, candidate in CANDIDATES.items():
        binary = Path(candidate["binary"])
        rows[name] = {
            "kind": candidate["kind"], "binary": str(binary), "binary_sha256": sha256_file(binary),
            "command": candidate["command"], "version_command": candidate["version"],
            "version_output": _version(candidate["version"]) if binary.is_file() else None,
        }
    return rows


def write_inventory(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "v1.8-candidate-inventory.json"
    path.write_text(json.dumps(inventory(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def evaluate_v18(record: RunRecord, run_dir: Path, client: str, server: str = "openssl-3.5.6-default") -> RunRecord:
    metrics = replace(record.metrics)
    pcap = Path(run_dir) / record.artifacts.get("pcap", "")
    summary = summarize_hellos(pcap.read_bytes()) if pcap.is_file() else None
    groups, shares = summary.client_hellos[0] if summary and summary.client_hellos else ([], [])
    groups, shares = [group_name(value) for value in groups], [group_name(value) for value in shares]
    if summary:
        metrics.hrr_pcap_present = summary.hrr_count > 0
        metrics.server_hello_count = summary.server_hello_count
        metrics.final_negotiated_group = group_name(summary.final_group)
    metrics.negotiated_group = metrics.final_negotiated_group
    metrics.is_hybrid = _is_hybrid(metrics.final_negotiated_group)
    metrics.downgrade_visible = bool(metrics.final_negotiated_group and not metrics.is_hybrid)
    metrics.handshake_result = "success" if metrics.server_hello_count else "failure"
    metrics.client_precondition_verified = bool(groups)
    metrics.downgrade_flagged = None
    candidate = CANDIDATES[client]
    record = replace(record, metrics=metrics, manipulation_verified=bool(groups), provenance={
        "part": "candidate-client-survey", "client": client, "client_kind": candidate["kind"],
        "client_cmd": candidate["command"], "binary": candidate["binary"],
        "binary_sha256": sha256_file(Path(candidate["binary"])), "client_hello_groups": groups,
        "client_hello_key_shares": shares, "classification": classify(groups, shares),
        "server": server, "server_selection_type": SERVER_SELECTION_TYPES.get(server, "unknown"),
        "server_cmd": SURVEY_SERVER if server == "openssl-3.5.6-default" else SERVERS[server],
    })
    record.to_json_path(run_dir)
    return record


def run_v18(
    repetitions: int, output_dir: Path | None = None, scenario_runner=run_scenario,
    clients: tuple[str, ...] | None = None,
) -> list[RunRecord]:
    out_dir = Path(output_dir or v18_output_dir())
    selected = clients or tuple(CANDIDATES)
    if clients is None and out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    existing = [client for client in selected if any(out_dir.glob(f"openssl_client-default-v18_r*_{client}.json"))]
    if existing:
        raise RuntimeError(f"{out_dir} already has records for: {', '.join(existing)}")
    write_inventory(out_dir)
    records = []
    for repetition in range(1, repetitions + 1):
        for client in selected:
            spec = survey_spec(client, repetition, out_dir)
            records.append(evaluate_v18(scenario_runner(spec), out_dir, client))
    return records


def run_e8(
    repetitions: int, output_dir: Path, scenario_runner=run_scenario,
    servers: tuple[str, ...] | None = None,
) -> list[RunRecord]:
    """Run the observed non-hybrid-first default against explicit server-selection types."""
    out_dir = Path(output_dir)
    selected = servers or E8_SERVERS
    existing = [server for server in selected
                if any(out_dir.glob(f"openssl_actual-client-e8_r*_{server}--botan.json"))]
    if existing:
        raise RuntimeError(f"{out_dir} already has records for: {', '.join(existing)}")
    write_inventory(out_dir)
    records = []
    for repetition in range(1, repetitions + 1):
        for server in selected:
            for client in E8_CLIENTS:
                spec = e8_spec(server, client, repetition, out_dir)
                records.append(evaluate_v18(scenario_runner(spec), out_dir, client, server))
    return records


def render_v18(run_dir: Path) -> str:
    counts: dict[tuple[str, str, str, str], int] = {}
    for path in sorted(Path(run_dir).glob("*.json")):
        if path.name == "v1.8-candidate-inventory.json":
            continue
        record = RunRecord.from_json(path)
        if record.fault_type not in ("client-default-v18", "actual-client-e8"):
            continue
        p = record.provenance
        key = (f"{p['client']} -> {p['server']}", p["classification"], ",".join(p["client_hello_groups"]),
               ",".join(p["client_hello_key_shares"]))
        counts[key] = counts.get(key, 0) + 1
    lines = ["| client | classification | supported_groups (order) | key_share | runs |",
             "|---|---|---|---|---:|"]
    lines += [f"| {client} | {kind} | {groups or '-'} | {shares or '-'} | {runs} |"
              for (client, kind, groups, shares), runs in sorted(counts.items())]
    return "\n".join(lines)


def reclassify(run_dir: Path) -> int:
    """Repair derived class labels from the preserved PCAP-derived ClientHello lists."""
    changed = 0
    for path in sorted(Path(run_dir).glob("*.json")):
        if path.name == "v1.8-candidate-inventory.json":
            continue
        record = RunRecord.from_json(path)
        if record.fault_type not in ("client-default-v18", "actual-client-e8"):
            continue
        p = record.provenance
        current = classify(p["client_hello_groups"], p["client_hello_key_shares"])
        selection_type = SERVER_SELECTION_TYPES.get(p.get("server"), "unknown")
        if p.get("classification") != current or p.get("server_selection_type") != selection_type:
            p["classification"] = current
            p["classification_schema"] = "v1.8-order-aware"
            p["server_selection_type"] = selection_type
            record.to_json_path(run_dir)
            changed += 1
    return changed


def preflight_v18() -> tuple[bool, str]:
    missing = [name for name, candidate in CANDIDATES.items() if not Path(candidate["binary"]).is_file()]
    if missing:
        return False, f"missing candidate binaries: {', '.join(missing)} (run tools/v18_setup.sh)"
    if not _port_free(PORT):
        return False, f"port {PORT} in use"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="v1.8 actual-client C2 survey")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repeat", type=int, metavar="N")
    mode.add_argument("--e8-repeat", type=int, metavar="N", help="run observed C2 defaults against E8 controls")
    mode.add_argument("--report", type=Path, metavar="DIR")
    mode.add_argument("--inventory", type=Path, metavar="DIR")
    mode.add_argument("--reclassify", type=Path, metavar="DIR")
    parser.add_argument("--clients", nargs="+", choices=tuple(CANDIDATES),
                        help="rerun only named candidates after moving incomplete records to a diagnostic directory")
    parser.add_argument("--output-dir", type=Path, metavar="PATH")
    parser.add_argument("--servers", nargs="+", choices=E8_SERVERS,
                        help="append only named server-selection controls with --e8-repeat")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(render_v18(arguments.report))
        return 0
    if arguments.inventory:
        print(write_inventory(arguments.inventory))
        return 0
    if arguments.reclassify:
        print(f"reclassified={reclassify(arguments.reclassify)}")
        return 0
    ok, reason = preflight_v18()
    if not ok:
        print(f"preflight failed: {reason}")
        return 1
    runner = run_e8 if arguments.e8_repeat else run_v18
    repetitions = arguments.e8_repeat or arguments.repeat
    if arguments.clients and arguments.e8_repeat:
        parser.error("--clients only applies to --repeat")
    if arguments.servers and not arguments.e8_repeat:
        parser.error("--servers only applies to --e8-repeat")
    call_kwargs = (
        {"servers": tuple(arguments.servers)} if arguments.servers else {}
    ) if arguments.e8_repeat else ({"clients": tuple(arguments.clients)} if arguments.clients else {})
    for record in runner(repetitions, arguments.output_dir, **call_kwargs):
        print(f"{record.run_id}: class={record.provenance['classification']} "
              f"groups={record.provenance['client_hello_groups']} "
              f"shares={record.provenance['client_hello_key_shares']} "
              f"final={record.metrics.final_negotiated_group}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
