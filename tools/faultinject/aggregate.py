from __future__ import annotations

import csv
import sys
from pathlib import Path

from faultinject.record import RunRecord


def aggregate(run_dir) -> dict:
    counts: dict = {}
    for p in sorted(Path(run_dir).glob("*.json")):
        r = RunRecord.from_json(p)
        c = counts.setdefault((r.implementation, r.fault_type),
                              {"total": 0, "verified": 0, "success": 0, "downgrade": 0})
        c["total"] += 1
        if r.manipulation_verified:
            c["verified"] += 1
        if r.metrics.handshake_result == "success":
            c["success"] += 1
        if r.metrics.downgrade_visible:
            c["downgrade"] += 1
    return counts


def aggregate_v11(run_dir) -> dict:
    counts: dict = {}
    for path in sorted(Path(run_dir).glob("*.json")):
        record = RunRecord.from_json(path)
        count = counts.setdefault(
            (record.implementation, record.condition),
            {"total": 0, "verified": 0, "success": 0, "downgrade": 0, "hrr": 0, "downgrade_flagged": 0},
        )
        count["total"] += 1
        count["verified"] += int(record.manipulation_verified)
        count["success"] += int(record.metrics.handshake_result == "success")
        count["downgrade"] += int(record.metrics.downgrade_visible)
        count["hrr"] += int(record.metrics.hrr_present is True)
        count["downgrade_flagged"] += int(record.metrics.downgrade_flagged is True)
    return counts


def meets_minimum(counts: dict, minimum: int = 10) -> bool:
    return len(counts) == 6 and all(c["verified"] >= minimum for c in counts.values())


def write_manifest(run_dir, out_csv=None) -> Path:
    run_dir = Path(run_dir)
    out_csv = Path(out_csv) if out_csv else run_dir / "manifest.csv"
    counts = aggregate(run_dir)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["implementation", "fault_type", "total", "verified", "success", "downgrade"])
        for (impl, fault), c in sorted(counts.items()):
            w.writerow([impl, fault, c["total"], c["verified"], c["success"], c["downgrade"]])
    return out_csv


def main(argv=None) -> int:
    run_dir = Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/phase-4"
    counts = aggregate(run_dir)
    path = write_manifest(run_dir)
    ok = meets_minimum(counts)
    print(f"manifest: {path}")
    for (impl, fault), c in sorted(counts.items()):
        print(f"  {impl}/{fault}: total={c['total']} verified={c['verified']} "
              f"success={c['success']} downgrade={c['downgrade']}")
    print("sample size OK" if ok else "sample size NOT met (need >=10 verified per combo)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
