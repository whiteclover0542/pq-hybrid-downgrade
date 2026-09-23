from faultinject.record import Metrics, RunRecord, run_id
from faultinject.analyze import comparison, render_markdown


def _w(d, impl, fault, rep, group, result, verified=True):
    rid = run_id(impl, fault, rep, "default")
    RunRecord(rid, impl, fault, rep, "default",
              Metrics(group, group is not None and "MLKEM" in (group or ""),
                      group is not None and "MLKEM" not in (group or ""), result),
              manipulation_verified=verified, artifacts={}).to_json_path(d)


def test_comparison_groups_and_counts(tmp_path):
    for rep in range(1, 11):
        _w(tmp_path, "openssl", "group-list", rep, "X25519", "success")
        _w(tmp_path, "openssl", "binding", rep, None, "failure")
    c = comparison(tmp_path)
    assert c[("openssl", "group-list")]["success"] == 10
    assert c[("openssl", "group-list")]["downgrade"] == 10
    assert c[("openssl", "group-list")]["groups"] == {"X25519"}
    assert c[("openssl", "binding")]["failure"] == 10
    assert c[("openssl", "binding")]["success"] == 0


def test_render_markdown_is_a_table(tmp_path):
    for rep in range(1, 11):
        _w(tmp_path, "openssl", "group-list", rep, "X25519", "success")
    md = render_markdown(tmp_path)
    assert "| implementation |" in md
    assert "openssl" in md and "X25519" in md
