from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

from faultinject.record import RunRecord

WARNING_RE = re.compile(r"(?i)\b(downgrad\w*|insecure|security warning|policy)\b")
ADVERTISED_RE = re.compile(
    r"(?i)(supported[_ ]groups|KEX algorithms)\s*[:=(].*(X25519MLKEM768|X25519Kyber768Draft00|sntrup761x25519)"
)
NEGOTIATED_RE = re.compile(r"(Negotiated TLS1\.3 group:|ECDHE group:|Peer Temp Key:|kex: algorithm:)\s*\S+")
NOT_COLLECTED = {
    "s_client -brief": "the client ran with -state -msg; no -brief output was captured",
    "keylog": "no key log was written; NSS key log lines hold labels, client randoms and secrets, not group names",
}


def audit_text(text: str | None) -> dict:
    if text is None:
        return {"explicit_warning": None, "mismatch_in_single_output": None, "evidence": "output missing"}
    warning = WARNING_RE.search(text)
    advertised = ADVERTISED_RE.search(text)
    negotiated = NEGOTIATED_RE.search(text)
    return {
        "explicit_warning": bool(warning),
        "mismatch_in_single_output": True if advertised and negotiated else "unsupported",
        "evidence": {
            "warning": warning.group(0) if warning else None,
            "advertised": advertised.group(0) if advertised else None,
            "negotiated": negotiated.group(0) if negotiated else None,
        },
    }


def tshark_summary(pcap: Path, runner=subprocess.run) -> str | None:
    try:
        result = runner(["tshark", "-r", str(pcap)], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return result.stdout if result.returncode == 0 else None


def summarize_paths(paths: dict[str, dict]) -> dict:
    warnings = [path["explicit_warning"] for path in paths.values()]
    mismatches = [path["mismatch_in_single_output"] for path in paths.values()]
    return {
        "explicit_warning": True if True in warnings else False if False in warnings else None,
        "mismatch_in_single_output": (
            True if True in mismatches else "unsupported" if "unsupported" in mismatches else None
        ),
        "basis": sorted(
            name for name, path in paths.items()
            if path["explicit_warning"] is True or path["mismatch_in_single_output"] is True
        ),
    }


def audit_record(record: RunRecord, run_dir: Path, runner=subprocess.run) -> dict:
    run_dir = Path(run_dir)

    def read(key: str) -> str | None:
        name = record.artifacts.get(key)
        path = run_dir / name if name else None
        return path.read_text(encoding="utf-8", errors="replace") if path and path.is_file() else None

    pcap = record.artifacts.get("pcap")
    paths = {
        "client_log": audit_text(read("client_log")),
        "server_log": audit_text(read("server_log")),
        "tshark_summary": audit_text(tshark_summary(run_dir / pcap, runner) if pcap else None),
        **{
            name: {"explicit_warning": None, "mismatch_in_single_output": "not_collected", "evidence": reason}
            for name, reason in NOT_COLLECTED.items()
        },
    }
    return {"paths": paths, **summarize_paths(paths)}


def recompute(run_dir: Path, runner=subprocess.run) -> list[dict]:
    rows = []
    for path in sorted(Path(run_dir).glob("*.json")):
        record = RunRecord.from_json(path)
        rows.append({
            "run_id": record.run_id,
            "implementation": record.implementation,
            "condition": record.condition,
            "audit": audit_record(record, Path(run_dir), runner),
        })
    return rows


def render_markdown(rows: list[dict]) -> str:
    counts: dict[tuple[str, str], Counter] = {}
    for row in rows:
        count = counts.setdefault((row["implementation"], row["condition"]), Counter())
        count["n"] += 1
        count[f"warning={row['audit']['explicit_warning']}"] += 1
        count[f"mismatch={row['audit']['mismatch_in_single_output']}"] += 1
    lines = [
        "| implementation | condition | n | warning true/false/unknown | single-output true/unsupported/unknown |",
        "|---|---|---:|---|---|",
    ]
    for (implementation, condition), count in sorted(counts.items()):
        lines.append(
            f"| {implementation} | {condition} | {count['n']} | "
            f"{count['warning=True']}/{count['warning=False']}/{count['warning=None']} | "
            f"{count['mismatch=True']}/{count['mismatch=unsupported']}/{count['mismatch=None']} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure audit visibility from preserved run artifacts")
    parser.add_argument("--v11", action="store_true", required=True, help="recompute the v1.1 records")
    parser.add_argument("--run-dir", type=Path, metavar="PATH", help="directory of JSON records")
    parser.add_argument("--out", type=Path, required=True, metavar="PATH", help="write per-run JSON here")
    arguments = parser.parse_args(argv)
    run_dir = arguments.run_dir or Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.1"
    rows = recompute(run_dir)
    arguments.out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(render_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
