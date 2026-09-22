from faultinject.record import Metrics, RunRecord, run_id
from faultinject.aggregate import aggregate, meets_minimum


def _write(dir, impl, fault, rep, verified, group, result):
    rid = run_id(impl, fault, rep, "default")
    RunRecord(rid, impl, fault, rep, "default",
              Metrics(group, group is not None and group.startswith("X25519ML"),
                      group is None or not group.startswith("X25519ML"), result),
              manipulation_verified=verified, artifacts={}).to_json_path(dir)


def test_meets_minimum_true_with_ten_verified_per_combo(tmp_path):
    for impl in ("openssl", "boringssl", "openssh"):
        for fault in ("group-list", "binding"):
            for rep in range(1, 11):
                _write(tmp_path, impl, fault, rep, True, "X25519", "success")
    counts = aggregate(tmp_path)
    assert counts[("openssl", "group-list")]["verified"] == 10
    assert len(counts) == 6
    assert meets_minimum(counts) is True         # 6조합 모두 ≥10 검증


def test_unverified_runs_not_counted_as_sample(tmp_path):
    for rep in range(1, 11):
        _write(tmp_path, "openssl", "binding", rep, False, None, "failure")
    counts = aggregate(tmp_path)
    assert counts[("openssl", "binding")]["total"] == 10
    assert counts[("openssl", "binding")]["verified"] == 0
    assert meets_minimum(counts) is False
