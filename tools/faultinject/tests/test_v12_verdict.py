from faultinject import analyze
from faultinject.analyze import EXPECTED_V12, comparison_v12, cve_verdict, render_v12_markdown
from faultinject.record import Metrics, RunRecord


def _write(run_dir, version, setting, rep, hrr, final, precondition=True, artifacts=True):
    name = f"openssl_server-setting_r{rep:02d}_{version}-{setting}"
    names = {
        "pcap": f"{name}.pcapng", "client_log": f"{name}-client.log",
        "server_log": f"{name}-server.log", "capture_log": f"{name}-capture.log",
    }
    if artifacts:
        for file_name in names.values():
            (run_dir / file_name).write_text("x", encoding="utf-8")
    RunRecord(
        name, "openssl", "server-setting", rep, f"{version}-{setting}",
        Metrics(final, final == "X25519MLKEM768", final == "X25519", "success" if final else "failure",
                hrr_pcap_present=hrr, hrr_log_present=hrr, server_hello_count=1 if final else 0,
                final_negotiated_group=final, client_precondition_verified=precondition),
        precondition,
        artifacts=names,
        provenance={"server_version": version, "server_setting": setting,
                    "server_bin_sha256": "s" * 64, "client_bin_sha256": "c" * 64},
        audit={"explicit_warning": False, "mismatch_in_single_output": "unsupported"},
    ).to_json_path(run_dir)


def _expected_matrix(run_dir, override=None):
    for (version, setting), (hrr, final) in EXPECTED_V12.items():
        for rep in range(1, 11):
            if override and override(version, setting, rep):
                continue
            _write(run_dir, version, setting, rep, hrr, final)


def test_expected_matrix_reproduces():
    assert EXPECTED_V12[("3.5.5", "S3")] == (False, "X25519")
    assert EXPECTED_V12[("3.5.6", "S3")] == (True, "X25519MLKEM768")


def test_verdict_true_only_when_every_condition_holds(tmp_path):
    _expected_matrix(tmp_path)

    assert cve_verdict(comparison_v12(tmp_path)) == (True, [])


def test_fixed_server_without_hrr_blocks_the_verdict(tmp_path):
    _expected_matrix(tmp_path, override=lambda version, setting, rep: (version, setting, rep) == ("3.5.6", "S3", 4))
    _write(tmp_path, "3.5.6", "S3", 4, False, "X25519")

    ok, reasons = cve_verdict(comparison_v12(tmp_path))

    assert ok is False
    assert any(reason.startswith("3.5.6 S3: PCAP HRR 9/10") for reason in reasons)


def test_missing_repetition_blocks_the_verdict(tmp_path):
    _expected_matrix(tmp_path, override=lambda version, setting, rep: (version, setting, rep) == ("3.5.5", "S1", 10))

    ok, reasons = cve_verdict(comparison_v12(tmp_path))

    assert ok is False
    assert any(reason.startswith("3.5.5 S1: repetitions") for reason in reasons)


def test_failed_precondition_or_missing_artifact_blocks_the_verdict(tmp_path):
    _expected_matrix(tmp_path, override=lambda version, setting, rep: (version, setting, rep) in {
        ("3.5.5", "S2", 1), ("3.5.5", "S2", 2)})
    _write(tmp_path, "3.5.5", "S2", 1, True, "X25519MLKEM768", precondition=False)
    _write(tmp_path, "3.5.5", "S2", 2, True, "X25519MLKEM768", artifacts=False)

    ok, reasons = cve_verdict(comparison_v12(tmp_path))

    assert ok is False
    assert any("precondition 9/10" in reason for reason in reasons)
    assert any("artifacts 9/10" in reason for reason in reasons)


def test_hrr_then_abort_counts_as_unknown_not_classical(tmp_path):
    _write(tmp_path, "3.5.6", "S3", 1, True, None)

    count = comparison_v12(tmp_path)[("3.5.6", "S3")]

    assert count["unknown"] == 1
    assert count["classical"] == 0


def test_v11_records_in_the_directory_are_ignored(tmp_path):
    RunRecord("openssl_condition_r01_base", "openssl", "condition", 1, "base",
              Metrics("X25519MLKEM768", True, False, "success"), True).to_json_path(tmp_path)

    assert comparison_v12(tmp_path) == {}


def test_render_and_cli(tmp_path, capsys):
    _expected_matrix(tmp_path)

    rendered = render_v12_markdown(tmp_path)
    assert "| 3.5.5 | S3 | 10/10 |" in rendered
    assert "CVE-2026-2673 verdict: reproduced" in rendered

    assert analyze.main(["--v12", "--run-dir", str(tmp_path)]) == 0
    assert "verdict" in capsys.readouterr().out
