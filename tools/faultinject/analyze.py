from __future__ import annotations
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


def main(argv=None) -> int:
    run_dir = Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/phase-4"
    print(render_markdown(run_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
