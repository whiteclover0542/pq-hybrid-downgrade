import json
import subprocess

from faultinject import audit
from faultinject.audit import audit_record, audit_text, recompute, summarize_paths, tshark_summary
from faultinject.record import Metrics, RunRecord

OPENSSL_MSG_LOG = (
    ">>> TLS 1.3, Handshake [length 0122], ClientHello\n"
    "    01 00 01 1e 03 03 5a 1b\n"
    "Negotiated TLS1.3 group: X25519MLKEM768\n"
)
SSH_LOG = (
    "debug2: KEX algorithms: sntrup761x25519-sha512@openssh.com,curve25519-sha256\n"
    "debug1: kex: algorithm: sntrup761x25519-sha512@openssh.com\n"
)


def test_openssl_msg_log_shows_the_result_but_not_the_advertised_names():
    result = audit_text(OPENSSL_MSG_LOG)

    assert result["explicit_warning"] is False
    assert result["mismatch_in_single_output"] == "unsupported"


def test_ssh_verbose_log_shows_both_offer_and_result():
    assert audit_text(SSH_LOG)["mismatch_in_single_output"] is True


def test_warning_signature_is_detected_and_kept_as_evidence():
    result = audit_text("WARNING: possible downgrade detected\n")

    assert result["explicit_warning"] is True
    assert "downgrade" in result["evidence"]["warning"]


def test_missing_output_is_unknown_not_false():
    assert audit_text(None) == {
        "explicit_warning": None,
        "mismatch_in_single_output": None,
        "evidence": "output missing",
    }


def test_tshark_summary_is_none_when_tshark_is_unavailable(tmp_path):
    def missing(*args, **kwargs):
        raise FileNotFoundError("tshark")

    assert tshark_summary(tmp_path / "x.pcapng", runner=missing) is None


def test_summary_prefers_true_then_false_then_unknown():
    paths = {
        "a": {"explicit_warning": False, "mismatch_in_single_output": "unsupported"},
        "b": {"explicit_warning": None, "mismatch_in_single_output": None},
        "c": {"explicit_warning": None, "mismatch_in_single_output": "not_collected"},
    }

    assert summarize_paths(paths) == {
        "explicit_warning": False,
        "mismatch_in_single_output": "unsupported",
        "basis": [],
    }
    paths["b"] = {"explicit_warning": True, "mismatch_in_single_output": True}
    summary = summarize_paths(paths)
    assert summary["explicit_warning"] is True
    assert summary["mismatch_in_single_output"] is True
    assert summary["basis"] == ["b"]


def _write_record(run_dir, name, client_text):
    (run_dir / f"{name}-client.log").write_text(client_text, encoding="utf-8")
    (run_dir / f"{name}-server.log").write_text("ACCEPT\n", encoding="utf-8")
    (run_dir / f"{name}.pcapng").write_bytes(b"pcap")
    record = RunRecord(
        name, "openssl", "condition", 1, "silent-downgrade",
        Metrics("X25519", False, True, "success"), True,
        artifacts={"client_log": f"{name}-client.log", "server_log": f"{name}-server.log", "pcap": f"{name}.pcapng"},
    )
    record.to_json_path(run_dir)
    return record


def _tshark(command, capture_output=True, text=True):
    return subprocess.CompletedProcess(command, 0, "1 0.0 127.0.0.1 → 127.0.0.1 TLSv1.3 Client Hello\n", "")


def test_audit_record_reports_every_path(tmp_path):
    record = _write_record(tmp_path, "openssl_condition_r01_silent-downgrade", OPENSSL_MSG_LOG)

    result = audit_record(record, tmp_path, runner=_tshark)

    assert set(result["paths"]) == {"client_log", "server_log", "tshark_summary", "s_client -brief", "keylog"}
    assert result["paths"]["keylog"]["mismatch_in_single_output"] == "not_collected"
    assert result["explicit_warning"] is False


def test_recompute_reads_records_without_modifying_them(tmp_path):
    _write_record(tmp_path, "openssl_condition_r01_silent-downgrade", OPENSSL_MSG_LOG)
    before = (tmp_path / "openssl_condition_r01_silent-downgrade.json").read_text(encoding="utf-8")

    rows = recompute(tmp_path, runner=_tshark)

    assert rows[0]["run_id"] == "openssl_condition_r01_silent-downgrade"
    assert rows[0]["condition"] == "silent-downgrade"
    assert (tmp_path / "openssl_condition_r01_silent-downgrade.json").read_text(encoding="utf-8") == before
    assert "| openssl | silent-downgrade |" in audit.render_markdown(rows)


def test_cli_writes_json(tmp_path, capsys):
    _write_record(tmp_path, "openssl_condition_r01_silent-downgrade", OPENSSL_MSG_LOG)
    out = tmp_path / "out.json"

    assert audit.main(["--v11", "--run-dir", str(tmp_path), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))[0]["implementation"] == "openssl"
