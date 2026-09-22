from types import SimpleNamespace
from faultinject.run import preflight

def _paths(tmp_path):
    b = tmp_path / "openssl"; b.write_text("x")
    for name in ("bssl", "ssh", "sshd"):
        (tmp_path / name).write_text("x")
    return {"openssl_bin": str(b), "bssl_bin": str(tmp_path/"bssl"),
            "ssh_bin": str(tmp_path/"ssh"), "sshd_bin": str(tmp_path/"sshd")}

def test_preflight_ok_when_provider_loads(tmp_path):
    runner = lambda *a, **k: SimpleNamespace(stdout="OpenSSL OQS Provider oqsprovider", returncode=0)
    ok, reason = preflight(_paths(tmp_path), {}, runner=runner)
    assert ok is True

def test_preflight_fails_when_provider_absent(tmp_path):
    runner = lambda *a, **k: SimpleNamespace(stdout="OpenSSL Default Provider", returncode=0)
    ok, reason = preflight(_paths(tmp_path), {}, runner=runner)
    assert ok is False
    assert "oqsprovider" in reason

def test_preflight_fails_when_binary_missing(tmp_path):
    paths = _paths(tmp_path); paths["ssh_bin"] = str(tmp_path / "nope")
    runner = lambda *a, **k: SimpleNamespace(stdout="oqsprovider", returncode=0)
    ok, reason = preflight(paths, {}, runner=runner)
    assert ok is False
    assert "ssh_bin" in reason
