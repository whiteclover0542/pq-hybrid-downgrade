from pathlib import Path

from faultinject.record import Metrics, RunRecord
from faultinject.verify_applied import mark, verify_binding, verify_group_list


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


def test_verify_group_list_is_false_when_pcap_matches_baseline():
    assert verify_group_list(BASELINE_PCAP, BASELINE_PCAP) is False


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
