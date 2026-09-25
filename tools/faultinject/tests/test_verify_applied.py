import shutil
from pathlib import Path

import pytest

from faultinject.record import Metrics, RunRecord
from faultinject import verify_applied
from faultinject.verify_applied import (
    mark,
    verify_binding,
    verify_condition,
    verify_group_list,
    verify_ssh_group_list,
)


BASELINE_PCAP = (
    Path(__file__).resolve().parents[3]
    / "docs/research/baselines/raw/openssl-67b5686b-baseline.pcapng"
)


def _record() -> RunRecord:
    return RunRecord(
        "openssl_group-list_r01_default",
        "openssl",
        "group-list",
        1,
        "default",
        Metrics("X25519", False, True, "success"),
        manipulation_verified=True,
        artifacts={},
    )


def test_mark_false_flags_tool_failure():
    result = mark(_record(), verified=False)

    assert result.manipulation_verified is False


def test_mark_true_keeps_result():
    result = mark(_record(), verified=True)

    assert result.manipulation_verified is True


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_verify_group_list_is_false_when_pcap_matches_baseline():
    assert verify_group_list(BASELINE_PCAP, BASELINE_PCAP) is False


def test_verify_group_list_rejects_an_empty_capture(monkeypatch):
    monkeypatch.setattr(
        verify_applied,
        "_supported_groups",
        lambda path: set() if path == "empty" else {"0x11ec"},
    )

    assert verify_group_list("empty", "baseline") is False


def test_verify_ssh_group_list_requires_a_changed_negotiated_kex(tmp_path):
    baseline = tmp_path / "baseline.log"
    run = tmp_path / "run.log"
    baseline.write_text(
        "debug1: kex: algorithm: sntrup761x25519-sha512@openssh.com\n",
        encoding="utf-8",
    )
    run.write_text("debug1: kex: algorithm: curve25519-sha256\n", encoding="utf-8")

    assert verify_ssh_group_list(run, baseline) is True


def test_verify_binding_requires_distinct_hashes(tmp_path):
    changed = tmp_path / "changed.log"
    unchanged = tmp_path / "unchanged.log"
    changed.write_text(
        "event=binding_mutation group_id=0x6399 before_sha256=aa after_sha256=bb\n",
        encoding="utf-8",
    )
    unchanged.write_text(
        "event=binding_mutation group_id=0x6399 before_sha256=aa after_sha256=aa\n",
        encoding="utf-8",
    )

    assert verify_binding(changed) is True
    assert verify_binding(unchanged) is False


def test_verify_condition_requires_hybrid_advertisement_and_classical_key_share(monkeypatch, tmp_path):
    record = _record()
    record.condition = "silent-downgrade"
    record.artifacts = {"pcap": "run.pcapng"}
    monkeypatch.setattr(
        verify_applied,
        "_client_hello_groups",
        lambda _: [([0x11EC, 0x001D], [0x001D, 0x11EC])],
    )

    assert verify_condition(record, tmp_path) is True


def test_verify_condition_requires_a_logged_strip_mutation(tmp_path):
    record = _record()
    record.condition = "onpath-strip"
    record.artifacts = {"proxy_log": "proxy.log"}
    (tmp_path / "proxy.log").write_text(
        "event=strip_mutation before_sha256=aa after_sha256=bb\n", encoding="utf-8"
    )

    assert verify_condition(record, tmp_path) is True
