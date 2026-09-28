from __future__ import annotations
import argparse
import sys
from pathlib import Path
from faultinject.record import RunRecord


def comparison(run_dir) -> dict:
    out: dict = {}
    for p in sorted(Path(run_dir).glob("*.json")):
        r = RunRecord.from_json(p)
        c = out.setdefault((r.implementation, r.fault_type),
                           {"n": 0, "verified": 0, "success": 0, "failure": 0,
                            "downgrade": 0, "groups": set()})
        c["n"] += 1
        if r.manipulation_verified:
            c["verified"] += 1
        if r.metrics.handshake_result == "success":
            c["success"] += 1
        else:
            c["failure"] += 1
        if r.metrics.downgrade_visible:
            c["downgrade"] += 1
        if r.metrics.negotiated_group:
            c["groups"].add(r.metrics.negotiated_group)
    return out


def comparison_v11(run_dir) -> dict:
    out: dict = {}
    for path in sorted(Path(run_dir).glob("*.json")):
        record = RunRecord.from_json(path)
        count = out.setdefault(
            (record.implementation, record.condition),
            {"n": 0, "verified": 0, "success": 0, "failure": 0, "hrr": 0, "downgrade_flagged": 0},
        )
        count["n"] += 1
        count["verified"] += int(record.manipulation_verified)
        count["success"] += int(record.metrics.handshake_result == "success")
        count["failure"] += int(record.metrics.handshake_result != "success")
        count["hrr"] += int(record.metrics.hrr_present is True)
        count["downgrade_flagged"] += int(record.metrics.downgrade_flagged is True)
    return out


def comparison_rows(run_dir) -> list[dict]:
    rows = []
    for (impl, fault), c in sorted(comparison(run_dir).items()):
        rows.append({"implementation": impl, "fault_type": fault, **c,
                     "groups": ",".join(sorted(c["groups"])) or "-"})
    return rows


def render_markdown(run_dir) -> str:
    header = ("| implementation | fault_type | verified/n | success | failure | "
              "downgrade | negotiated group(s) |\n"
              "|---|---|---|---|---|---|---|")
    lines = [header]
    for r in comparison_rows(run_dir):
        lines.append(f"| {r['implementation']} | {r['fault_type']} | "
                     f"{r['verified']}/{r['n']} | {r['success']} | {r['failure']} | "
                     f"{r['downgrade']} | {r['groups']} |")
    return "\n".join(lines)


def render_v11_markdown(run_dir) -> str:
    header = (
        "| implementation | condition | verified/n | success | failure | HRR | downgrade flagged |\n"
        "|---|---|---|---|---|---|---|"
    )
    lines = [header]
    for (implementation, condition), count in sorted(comparison_v11(run_dir).items()):
        lines.append(
            f"| {implementation} | {condition} | {count['verified']}/{count['n']} | "
            f"{count['success']} | {count['failure']} | {count['hrr']} | "
            f"{count['downgrade_flagged']} |"
        )
    return "\n".join(lines)


REQUIRED_ARTIFACTS_V12 = ("pcap", "client_log", "server_log", "capture_log")

# (server version, setting) -> (PCAP HRR expected in every run, expected final group); spec §2.2 / §5
EXPECTED_V12 = {
    ("3.5.5", "S1"): (False, "X25519"),
    ("3.5.6", "S1"): (False, "X25519"),
    ("3.5.5", "S2"): (True, "X25519MLKEM768"),
    ("3.5.6", "S2"): (True, "X25519MLKEM768"),
    ("3.5.5", "S3"): (False, "X25519"),
    ("3.5.6", "S3"): (True, "X25519MLKEM768"),
}


def comparison_v12(run_dir) -> dict:
    run_dir = Path(run_dir)
    out: dict = {}
    for path in sorted(run_dir.glob("*.json")):
        record = RunRecord.from_json(path)
        if record.fault_type != "server-setting":
            continue
        key = (record.provenance["server_version"], record.provenance["server_setting"])
        count = out.setdefault(key, {
            "n": 0, "repetitions": set(), "precondition": 0, "success": 0, "failure": 0,
            "hrr_pcap": 0, "hrr_log": 0, "hybrid": 0, "classical": 0, "unknown": 0,
            "explicit_warning": 0, "mismatch_in_single_output": 0,
            "artifacts_complete": 0, "provenance_complete": 0,
        })
        metrics = record.metrics
        final = metrics.final_negotiated_group
        count["n"] += 1
        count["repetitions"].add(record.repetition)
        count["precondition"] += int(metrics.client_precondition_verified is True)
        count["success"] += int(metrics.handshake_result == "success")
        count["failure"] += int(metrics.handshake_result != "success")
        count["hrr_pcap"] += int(metrics.hrr_pcap_present is True)
        count["hrr_log"] += int(metrics.hrr_log_present is True)
        count["hybrid" if final == "X25519MLKEM768" else "classical" if final == "X25519" else "unknown"] += 1
        count["explicit_warning"] += int(record.audit.get("explicit_warning") is True)
        count["mismatch_in_single_output"] += int(record.audit.get("mismatch_in_single_output") is True)
        count["artifacts_complete"] += int(all(
            record.artifacts.get(name)
            and (run_dir / record.artifacts[name]).is_file()
            and (run_dir / record.artifacts[name]).stat().st_size > 0
            for name in REQUIRED_ARTIFACTS_V12
        ))
        count["provenance_complete"] += int(bool(
            record.provenance.get("server_bin_sha256") and record.provenance.get("client_bin_sha256")
        ))
    return out


def cve_verdict(counts: dict, repetitions: int = 10) -> tuple[bool, list[str]]:
    failures: list[str] = []
    for (version, setting), (hrr_expected, final_expected) in EXPECTED_V12.items():
        label = f"{version} {setting}"
        count = counts.get((version, setting))
        if count is None:
            failures.append(f"{label}: no records")
            continue
        n = count["n"]
        if n != repetitions or count["repetitions"] != set(range(1, repetitions + 1)):
            failures.append(f"{label}: repetitions {sorted(count['repetitions'])} (n={n})")
        for field_name in ("precondition", "artifacts_complete", "provenance_complete", "success"):
            if count[field_name] != n:
                failures.append(f"{label}: {field_name.split('_')[0]} {count[field_name]}/{n}")
        if count["hrr_pcap"] != (n if hrr_expected else 0):
            failures.append(f"{label}: PCAP HRR {count['hrr_pcap']}/{n}, expected {'all' if hrr_expected else 'none'}")
        final_count = count["hybrid"] if final_expected == "X25519MLKEM768" else count["classical"]
        if final_count != n:
            failures.append(f"{label}: final {final_expected} {final_count}/{n}")
    return (not failures, failures)


def render_v12_markdown(run_dir) -> str:
    counts = comparison_v12(run_dir)
    lines = [
        "| server | setting | precondition/n | success | failure | HRR (PCAP) | HRR (log) | "
        "hybrid | classical | unknown | explicit warning | single-output mismatch |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for (version, setting), count in sorted(counts.items()):
        lines.append(
            f"| {version} | {setting} | {count['precondition']}/{count['n']} | {count['success']} | "
            f"{count['failure']} | {count['hrr_pcap']} | {count['hrr_log']} | {count['hybrid']} | "
            f"{count['classical']} | {count['unknown']} | {count['explicit_warning']} | "
            f"{count['mismatch_in_single_output']} |"
        )
    ok, reasons = cve_verdict(counts)
    lines.append("")
    lines.append("CVE-2026-2673 verdict: " + ("reproduced" if ok else "not reproduced — " + "; ".join(reasons)))
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render fault-injection analysis")
    parser.add_argument("--v11", action="store_true", help="read v1.1 condition records")
    parser.add_argument("--v12", action="store_true", help="read v1.2 server-setting records")
    parser.add_argument("--run-dir", type=Path, metavar="PATH", help="directory of v1.1/v1.2 JSON records")
    arguments = parser.parse_args(argv)
    if arguments.run_dir and not (arguments.v11 or arguments.v12):
        parser.error("--run-dir is only valid with --v11 or --v12")
    raw = Path(__file__).resolve().parents[2] / "docs/research/baselines/raw"
    if arguments.v12:
        print(render_v12_markdown(arguments.run_dir or raw / "v1.2"))
        return 0
    if arguments.v11:
        print(render_v11_markdown(arguments.run_dir or raw / "v1.1"))
        return 0
    print(render_markdown(raw / "phase-4"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
