from pathlib import Path

from faultinject.conditions import condition_spec

PATHS = {"openssl_bin": "/x/openssl", "openssl_cert": "/x/c.pem",
         "bssl_bin": "/x/bssl", "boring_cert": "/x/bc.pem", "boring_key": "/x/bk.pem",
         "ssh_bin": "/x/ssh", "sshd_bin": "/x/sshd", "sshd_config": "/x/sshd_config",
         "ssh_key": "/x/key"}

def test_openssl_silent_downgrade_orders_classical_first():
    s = condition_spec("openssl", "silent-downgrade", 1, {}, Path("/tmp"), PATHS)
    j = " ".join(s.client_cmd)
    # client advertises hybrid AND classical, classical key_share first
    assert "-groups X25519:X25519MLKEM768" in j
    assert "-msg" in j            # so HRR parser can see ServerHello
    assert s.condition == "silent-downgrade"
    assert s.fault_type == "condition"

def test_openssl_base_sends_hybrid_key_share_first():
    s = condition_spec("openssl", "base", 1, {}, Path("/tmp"), PATHS)
    assert "-groups X25519MLKEM768:X25519" in " ".join(s.client_cmd)

def test_boringssl_silent_downgrade_orders_classical_first():
    s = condition_spec("boringssl", "silent-downgrade", 1, {}, Path("/tmp"), PATHS)
    assert "-curves X25519:X25519Kyber768Draft00" in " ".join(s.client_cmd)

def test_ssh_order_condition_builds():
    s = condition_spec("openssh", "ssh-order", 1, {}, Path("/tmp"), PATHS)
    assert s.impl == "openssh" and s.condition == "ssh-order"
