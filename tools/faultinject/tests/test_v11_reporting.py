from faultinject.aggregate import aggregate_v11
from faultinject.analyze import comparison_v11
from faultinject.record import Metrics, RunRecord


def _record(condition: str) -> RunRecord:
    return RunRecord(
        f"openssl_condition_r01_{condition}",
        "openssl",
        "condition",
        1,
        condition,
        Metrics("X25519", False, True, "success", hrr_present=False, downgrade_flagged=False),
        manipulation_verified=True,
    )


def test_v11_aggregation_keeps_condition_and_new_metrics(tmp_path):
    _record("silent-downgrade").to_json_path(tmp_path)

    counts = aggregate_v11(tmp_path)

    assert counts[("openssl", "silent-downgrade")]["hrr"] == 0
    assert counts[("openssl", "silent-downgrade")]["downgrade_flagged"] == 0


def test_v11_analysis_keeps_condition_axis(tmp_path):
    _record("onpath-strip").to_json_path(tmp_path)

    rows = comparison_v11(tmp_path)

    assert rows[("openssl", "onpath-strip")]["hrr"] == 0
