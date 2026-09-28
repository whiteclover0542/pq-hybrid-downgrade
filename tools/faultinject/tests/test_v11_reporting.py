from faultinject import aggregate, analyze
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


def test_v11_aggregate_cli_is_read_only_and_uses_requested_directory(monkeypatch, tmp_path, capsys):
    _record("silent-downgrade").to_json_path(tmp_path)
    before = {path.name for path in tmp_path.iterdir()}
    monkeypatch.setattr(
        aggregate,
        "write_manifest",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy writer used")),
    )

    assert aggregate.main(["--v11", "--run-dir", str(tmp_path)]) == 0

    assert "openssl/silent-downgrade" in capsys.readouterr().out
    assert {path.name for path in tmp_path.iterdir()} == before


def test_v11_analysis_cli_is_read_only_and_uses_requested_directory(tmp_path, capsys):
    _record("onpath-strip").to_json_path(tmp_path)
    before = {path.name for path in tmp_path.iterdir()}

    assert analyze.main(["--v11", "--run-dir", str(tmp_path)]) == 0

    assert "| openssl | onpath-strip |" in capsys.readouterr().out
    assert {path.name for path in tmp_path.iterdir()} == before
