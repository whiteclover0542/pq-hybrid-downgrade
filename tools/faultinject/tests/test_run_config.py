from faultinject.run import default_output_dir, phase2_environment, phase2_paths, smoke_specs


def test_phase2_paths_use_fixed_custom_binaries():
    paths = phase2_paths()

    assert paths["openssl_bin"] == "/root/pq-hybrid-phase2/install/openssl/bin/openssl"
    assert paths["bssl_bin"] == "/root/pq-hybrid-phase2/build/boringssl/tool/bssl"
    assert paths["ssh_bin"] == "/root/pq-hybrid-phase2/openssh/ssh"


def test_phase2_environment_loads_custom_oqs_provider():
    environment = phase2_environment()

    assert environment["OPENSSL_MODULES"] == "/root/pq-hybrid-phase2/install/openssl/lib64/ossl-modules"
    assert "/root/pq-hybrid-phase2/install/openssl/lib64" in environment["LD_LIBRARY_PATH"]


def test_default_output_dir_is_versioned_research_artifact_location():
    assert default_output_dir().as_posix().endswith("docs/research/baselines/raw/phase-3")


def test_smoke_specs_cover_three_implementations_and_two_fault_types(tmp_path):
    specs = smoke_specs(output_dir=tmp_path)

    assert {(spec.impl, spec.fault_type) for spec in specs} == {
        ("openssl", "group-list"),
        ("openssl", "binding"),
        ("boringssl", "group-list"),
        ("boringssl", "binding"),
        ("openssh", "group-list"),
        ("openssh", "binding"),
    }
