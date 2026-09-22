from faultinject.run import phase2_environment, phase2_paths


def test_phase2_paths_use_fixed_custom_binaries():
    paths = phase2_paths()

    assert paths["openssl_bin"] == "/root/pq-hybrid-phase2/install/openssl/bin/openssl"
    assert paths["bssl_bin"] == "/root/pq-hybrid-phase2/build/boringssl/tool/bssl"
    assert paths["ssh_bin"] == "/root/pq-hybrid-phase2/openssh/ssh"


def test_phase2_environment_loads_custom_oqs_provider():
    environment = phase2_environment()

    assert environment["OPENSSL_MODULES"] == "/root/pq-hybrid-phase2/install/openssl/lib64/ossl-modules"
    assert "/root/pq-hybrid-phase2/install/openssl/lib64" in environment["LD_LIBRARY_PATH"]
