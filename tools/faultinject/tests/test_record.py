from faultinject.record import Metrics, RunRecord, run_id


def test_run_id_format():
    assert run_id("openssl", "group-list", 1, "default") == "openssl_group-list_r01_default"


def test_record_roundtrip(tmp_path):
    record = RunRecord(
        run_id=run_id("boringssl", "binding", 3, "default"),
        implementation="boringssl",
        fault_type="binding",
        repetition=3,
        condition="default",
        metrics=Metrics(
            negotiated_group="X25519Kyber768Draft00",
            is_hybrid=True,
            downgrade_visible=False,
            handshake_result="success",
        ),
        manipulation_verified=True,
        artifacts={"client_log": "a.log"},
    )

    path = record.to_json_path(tmp_path)

    assert path.name == "boringssl_binding_r03_default.json"
    loaded = RunRecord.from_json(path)
    assert loaded.metrics.negotiated_group == "X25519Kyber768Draft00"
    assert loaded.manipulation_verified is True
