from pathlib import Path
from faultinject.record import Metrics, RunRecord, run_id


def test_metrics_has_v11_fields_with_defaults():
    m = Metrics("X25519", False, True, "success")
    assert m.hrr_present is None
    assert m.downgrade_flagged is None
    assert m.advertised_hybrid is None


def test_v11_roundtrip(tmp_path):
    m = Metrics("X25519", False, True, "success",
                hrr_present=False, downgrade_flagged=False, advertised_hybrid=True)
    rec = RunRecord(run_id("openssl", "silent-downgrade", 1, "default"),
                    "openssl", "silent-downgrade", 1, "default", m,
                    manipulation_verified=True, artifacts={})
    p = rec.to_json_path(tmp_path)
    loaded = RunRecord.from_json(p)
    assert loaded.metrics.hrr_present is False
    assert loaded.metrics.advertised_hybrid is True


def test_reads_v10_json_without_new_fields():
    # a real v1.0 phase-4 record has no hrr_present/downgrade_flagged/advertised_hybrid
    v10 = Path(__file__).resolve().parents[3] / \
        "docs/research/baselines/raw/phase-4/openssl_group-list_r01_default.json"
    rec = RunRecord.from_json(v10)
    assert rec.metrics.hrr_present is None  # absent field -> default
