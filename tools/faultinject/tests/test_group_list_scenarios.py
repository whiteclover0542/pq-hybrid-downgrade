from pathlib import Path

from faultinject.fault_group_list import group_list_spec


PATHS = {
    "openssl_bin": "/root/pq-hybrid-phase2/install/openssl/bin/openssl",
    "openssl_cert": "/root/pq-hybrid-phase2/openssl/apps/server.pem",
}


def test_openssl_group_list_omits_hybrid():
    spec = group_list_spec("openssl", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    joined = " ".join(spec.client_cmd)
    assert "X25519MLKEM768" not in joined
    assert "-groups" in joined
    assert spec.fault_type == "group-list"
    assert "/root/pq-hybrid-phase2/openssl/apps/server.pem" in spec.server_cmd
