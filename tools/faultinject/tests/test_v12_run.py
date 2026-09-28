import shutil
import subprocess
from pathlib import Path

import pytest

from faultinject import v12
from faultinject.record import Metrics, RunRecord
from faultinject.v12 import evaluate_v12, provenance_for, run_v12, v12_paths, v12_spec

RAW_V11 = Path(__file__).resolve().parents[3] / "docs/research/baselines/raw/v1.1"


def _no_tshark(*args, **kwargs):
    raise FileNotFoundError("tshark")


def _record(run_dir, fixture=None):
    name = "openssl_server-setting_r01_3.5.5-S3"
    if fixture:
        shutil.copy(RAW_V11 / f"{fixture}.pcapng", run_dir / f"{name}.pcapng")
        shutil.copy(RAW_V11 / f"{fixture}-client.log", run_dir / f"{name}-client.log")
    else:
        (run_dir / f"{name}-client.log").write_text("", encoding="utf-8")
    (run_dir / f"{name}-server.log").write_text("ACCEPT\n", encoding="utf-8")
    return RunRecord(
        name, "openssl", "server-setting", 1, "3.5.5-S3",
        Metrics("X25519", False, True, "success", advertised_hybrid=True, downgrade_flagged=False),
        False,
        artifacts={
            "client_log": f"{name}-client.log",
            "server_log": f"{name}-server.log",
            **({"pcap": f"{name}.pcapng"} if fixture else {}),
        },
    )


def test_evaluate_uses_the_pcap_as_primary_evidence(tmp_path):
    record = _record(tmp_path, "openssl_condition_r01_silent-downgrade")

    result = evaluate_v12(record, tmp_path, {"server_version": "3.5.5"}, runner=_no_tshark)

    assert result.metrics.hrr_pcap_present is False
    assert result.metrics.hrr_log_present is False
    assert result.metrics.server_hello_count == 1
    assert result.metrics.final_negotiated_group == "X25519"
    assert result.metrics.client_precondition_verified is True
    assert result.manipulation_verified is True
    assert result.metrics.downgrade_flagged is None
    assert result.provenance == {"server_version": "3.5.5"}
    assert result.audit["paths"]["tshark_summary"]["explicit_warning"] is None
    assert RunRecord.from_json(tmp_path / f"{record.run_id}.json") == result


def test_evaluate_counts_hrr_from_the_pcap(tmp_path):
    result = evaluate_v12(_record(tmp_path, "openssl_condition_r01_onpath-strip"), tmp_path, {}, runner=_no_tshark)

    assert result.metrics.hrr_pcap_present is True
    assert result.metrics.hrr_log_present is True


def test_evaluate_does_not_mutate_the_input_record(tmp_path):
    record = _record(tmp_path, "openssl_condition_r01_silent-downgrade")

    result = evaluate_v12(record, tmp_path, {"server_version": "3.5.5"}, runner=_no_tshark)

    # Input record should not be mutated
    assert record.metrics.hrr_pcap_present is None
    assert record.metrics.downgrade_flagged is False
    # Result should have updated values
    assert result.metrics.hrr_pcap_present is False
    assert result.metrics.downgrade_flagged is None


def test_missing_pcap_is_excluded_not_counted_as_no_hrr(tmp_path):
    result = evaluate_v12(_record(tmp_path), tmp_path, {}, runner=_no_tshark)

    assert result.metrics.hrr_pcap_present is None
    assert result.metrics.final_negotiated_group is None
    assert result.metrics.client_precondition_verified is False
    assert result.manipulation_verified is False


def test_provenance_records_both_binaries_and_the_setting():
    paths = v12_paths()
    spec = v12_spec("3.5.6", "S3", 1, Path("/tmp/v12"), paths)

    provenance = provenance_for(spec, paths, {"client_bin": "c" * 64, "server_bin_3.5.6": "s" * 64})

    assert provenance["server_version"] == "3.5.6"
    assert provenance["server_setting"] == "S3"
    assert provenance["server_groups_arg"] == "DEFAULT"
    assert provenance["server_bin_sha256"] == "s" * 64
    assert provenance["client_bin_sha256"] == "c" * 64
    assert provenance["client_groups_arg"] == "X25519:X25519MLKEM768"
    assert provenance["server_env"]["LD_LIBRARY_PATH"].endswith("openssl-3.5.6/lib64")
    assert provenance["server_cmd"] == spec.server_cmd
    assert provenance["client_cmd"] == spec.client_cmd

    # S4 (None) should map to "(omitted)"
    spec4 = v12_spec("3.5.5", "S4", 1, Path("/tmp/v12"), paths)
    provenance4 = provenance_for(spec4, paths, {})
    assert provenance4["server_groups_arg"] == "(omitted)"


def test_run_refuses_a_non_empty_output_directory(tmp_path):
    (tmp_path / "old.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="not empty"):
        run_v12(1, output_dir=tmp_path, scenario_runner=lambda spec: pytest.fail("must not run"))


def test_run_evaluates_every_scenario(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(v12, "evaluate_v12", lambda record, run_dir, provenance, runner: seen.append(provenance) or record)

    def fake_scenario(spec):
        return RunRecord(f"openssl_server-setting_r{spec.repetition:02d}_{spec.condition}", "openssl",
                         "server-setting", spec.repetition, spec.condition,
                         Metrics(None, False, False, "failure"), False)

    records = run_v12(1, output_dir=tmp_path, scenario_runner=fake_scenario)

    assert len(records) == 6
    assert {(item["server_version"], item["server_setting"]) for item in seen} == {
        (version, setting) for version in ("3.5.5", "3.5.6") for setting in ("S1", "S2", "S3")
    }


def test_cli_stops_when_preflight_fails(monkeypatch, capsys):
    monkeypatch.setattr(v12, "preflight_v12", lambda paths: (False, "ports in use: [8545]"))
    monkeypatch.setattr(v12, "run_v12", lambda *args, **kwargs: pytest.fail("must not run"))

    assert v12.main(["--repeat", "10"]) == 1
    assert "ports in use" in capsys.readouterr().out


def test_cli_routes_settings_and_output_dir(monkeypatch, tmp_path):
    received = {}
    monkeypatch.setattr(v12, "preflight_v12", lambda paths: (True, "ok"))
    monkeypatch.setattr(v12, "run_v12", lambda repetitions, output_dir=None, settings=(): received.update(
        repetitions=repetitions, output_dir=output_dir, settings=settings) or [])

    assert v12.main(["--repeat", "10", "--settings", "S4", "--output-dir", str(tmp_path)]) == 0
    assert received == {"repetitions": 10, "output_dir": tmp_path, "settings": ("S4",)}


def test_cli_rejects_unknown_settings():
    with pytest.raises(SystemExit):
        v12.main(["--repeat", "1", "--settings", "S9"])
