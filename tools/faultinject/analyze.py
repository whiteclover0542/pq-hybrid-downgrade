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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render fault-injection analysis")
    parser.add_argument("--v11", action="store_true", help="read v1.1 condition records")
    parser.add_argument("--run-dir", type=Path, metavar="PATH", help="directory of v1.1 JSON records")
    arguments = parser.parse_args(argv)
    if arguments.run_dir and not arguments.v11:
        parser.error("--run-dir is only valid with --v11")
    if arguments.v11:
        run_dir = arguments.run_dir or Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.1"
        print(render_v11_markdown(run_dir))
        return 0

    run_dir = Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/phase-4"
    print(render_markdown(run_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
