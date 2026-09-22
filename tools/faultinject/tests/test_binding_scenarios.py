from pathlib import Path

from faultinject.fault_binding import binding_spec


PATHS = {
    "openssl_bin": "/root/pq-hybrid-phase2/install/openssl/bin/openssl",
    "openssl_cert": "/root/pq-hybrid-phase2/openssl/apps/server.pem",
    "bssl_bin": "/root/pq-hybrid-phase2/build/boringssl/tool/bssl",
    "boring_cert": "/root/pq-hybrid-phase2/boring-cert.pem",
    "boring_key": "/root/pq-hybrid-phase2/boring-key.pem",
    "ssh_bin": "/root/pq-hybrid-phase2/openssh/ssh",
    "sshd_bin": "/root/pq-hybrid-phase2/openssh/sshd",
    "sshd_config": "/root/pq-hybrid-phase2/openssh-run/sshd_config",
    "ssh_key": "/root/pq-hybrid-phase2/openssh-run/client_ed25519",
}


def test_openssl_binding_uses_a_proxy_and_fixed_hybrid_group():
    spec = binding_spec("openssl", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    assert spec.fault_type == "binding"
    assert spec.listen_port == 9443
    assert spec.server_listen_port == 8445
    assert spec.proxy_upstream_port == 8445
    assert "X25519MLKEM768" in spec.client_cmd
    assert spec.proxy_mutate is not None
    assert spec.proxy_log is not None


def test_openssh_binding_uses_an_isolated_proxy_and_private_key():
    spec = binding_spec("openssh", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    assert spec.listen_port == 2225
    assert spec.server_listen_port == 2224
    assert spec.proxy_upstream_port == 2224
    assert "-i" in spec.client_cmd
    assert PATHS["ssh_key"] in spec.client_cmd
