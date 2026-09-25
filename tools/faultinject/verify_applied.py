from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.harness import parse_group
from faultinject.record import RunRecord


def _supported_groups(pcap: str | Path) -> set[str]:
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "tls.handshake.extensions_supported_group",
            "-T",
            "fields",
            "-e",
            "tls.handshake.extensions_supported_group",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "tshark could not read pcap")
    return {value for line in result.stdout.splitlines() for value in line.split(",") if value}


def _client_hello_groups(pcap: str | Path) -> list[tuple[list[int], list[int]]]:
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap), "-Y", "tls.handshake.type==1", "-T", "fields",
            "-e", "tls.handshake.extensions_supported_group",
            "-e", "tls.handshake.extensions_key_share_group",
        ],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "tshark could not read pcap")

    def ids(raw: str) -> list[int]:
        return [int(value, 0) for value in raw.split(",") if value]

    return [tuple(map(ids, line.split("\t", 1))) for line in result.stdout.splitlines() if "\t" in line]


def verify_group_list(run_pcap: str | Path, baseline_pcap: str | Path) -> bool:
    run_groups = _supported_groups(run_pcap)
    baseline_groups = _supported_groups(baseline_pcap)
    return bool(run_groups) and bool(baseline_groups) and run_groups != baseline_groups


def verify_ssh_group_list(run_log: str | Path, baseline_log: str | Path) -> bool:
    run_group = parse_group("openssh", Path(run_log).read_text(encoding="utf-8"))
    baseline_group = parse_group("openssh", Path(baseline_log).read_text(encoding="utf-8"))
    return run_group is not None and baseline_group is not None and run_group != baseline_group


def verify_binding(proxy_log: str | Path) -> bool:
    for line in Path(proxy_log).read_text(encoding="utf-8").splitlines():
        fields = dict(field.split("=", 1) for field in line.split() if "=" in field)
        if (
            fields.get("event") == "binding_mutation"
            and fields.get("before_sha256")
            and fields.get("after_sha256")
            and fields["before_sha256"] != fields["after_sha256"]
        ):
            return True
    return False


def verify_condition(record: RunRecord, output_dir: str | Path) -> bool:
    output_dir = Path(output_dir)
    if record.condition == "silent-downgrade":
        groups = _client_hello_groups(output_dir / record.artifacts["pcap"])
        return any(
            any(group in {0x11EC, 0x6399} for group in advertised)
            and bool(key_shares)
            and key_shares[0] == 0x001D
            for advertised, key_shares in groups
        )
    if record.condition == "onpath-strip":
        for line in (output_dir / record.artifacts["proxy_log"]).read_text(encoding="utf-8").splitlines():
            fields = dict(field.split("=", 1) for field in line.split() if "=" in field)
            if fields.get("event") == "strip_mutation" and fields.get("before_sha256") != fields.get("after_sha256"):
                return True
        return False
    return True


def mark(record: RunRecord, verified: bool) -> RunRecord:
    return replace(record, manipulation_verified=verified)
