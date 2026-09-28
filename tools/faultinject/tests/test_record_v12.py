from pathlib import Path

from faultinject.record import Metrics, RunRecord

V11_JSON = (
    Path(__file__).resolve().parents[3]
    / "docs/research/baselines/raw/v1.1/openssl_condition_r01_base.json"
)


def test_v12_fields_round_trip(tmp_path):
    record = RunRecord(
        "openssl_server-setting_r01_3.5.6-S3", "openssl", "server-setting", 1, "3.5.6-S3",
        Metrics("X25519MLKEM768", True, False, "success", hrr_pcap_present=True,
                hrr_log_present=True, server_hello_count=1,
                final_negotiated_group="X25519MLKEM768", client_precondition_verified=True),
        manipulation_verified=True,
        artifacts={"pcap": "x.pcapng"},
        provenance={"server_version": "3.5.6", "server_setting": "S3"},
        audit={"explicit_warning": False},
    )

    loaded = RunRecord.from_json(record.to_json_path(tmp_path))

    assert loaded == record


def test_v11_records_still_load_with_empty_v12_fields():
    loaded = RunRecord.from_json(V11_JSON)

    assert loaded.metrics.hrr_pcap_present is None
    assert loaded.metrics.final_negotiated_group is None
    assert loaded.provenance == {}
    assert loaded.audit == {}
