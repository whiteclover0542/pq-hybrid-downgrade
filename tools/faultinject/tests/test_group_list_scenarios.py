from pathlib import Path

from faultinject.fault_group_list import group_list_spec


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


def test_openssl_group_list_omits_hybrid():
    spec = group_list_spec("openssl", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    joined = " ".join(spec.client_cmd)
    assert "X25519MLKEM768" not in joined
    assert "-groups" in joined
    assert spec.fault_type == "group-list"
    assert "/root/pq-hybrid-phase2/openssl/apps/server.pem" in spec.server_cmd
    assert spec.listen_port == 8443
    assert spec.capture_traffic is True


def test_boringssl_group_list_uses_fixed_certificate_and_accepts_multiple_connections():
    spec = group_list_spec("boringssl", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    assert "-cert" in spec.server_cmd
    assert "/root/pq-hybrid-phase2/boring-cert.pem" in spec.server_cmd
    assert "-key" in spec.server_cmd
    assert "/root/pq-hybrid-phase2/boring-key.pem" in spec.server_cmd
    assert "-loop" in spec.server_cmd
    assert spec.listen_port == 8444


def test_openssh_group_list_starts_an_isolated_loopback_server():
    spec = group_list_spec("openssh", 1, env={}, out_dir=Path("/tmp"), paths=PATHS)

    assert spec.server_cmd[0] == PATHS["sshd_bin"]
    assert "-D" in spec.server_cmd
    assert "-p" in spec.server_cmd
    assert "2223" in spec.server_cmd
    assert "-i" in spec.client_cmd
    assert PATHS["ssh_key"] in spec.client_cmd
    assert spec.listen_port == 2223
