from pathlib import Path

from faultinject.record import Metrics, RunRecord
from faultinject.v18 import CANDIDATES, E8_SERVERS, classify, e8_spec, render_v18, survey_spec


def test_classification_requires_hybrid_advertisement_before_calling_a_client_c2():
    assert classify(["X25519"], ["X25519"]) == "no-hybrid-advertisement"
    assert classify(["X25519MLKEM768", "X25519"], ["X25519MLKEM768"]) == "C1-hybrid-first-share"
    assert classify(["X25519MLKEM768", "X25519"], ["X25519"]) == "C2-hybrid-first-share-omitted"
    assert classify(["X25519", "X25519MLKEM768"], ["X25519"]) == "C3-classical-first-share"


def test_candidates_keep_default_group_selection_unmodified():
    assert {"gnutls", "botan", "wolfssl", "mbedtls", "s2n-tls", "java", "node-openssl", "python-openssl"} <= set(CANDIDATES)
    for client in CANDIDATES:
        command = survey_spec(client, 1, Path("/tmp/v18")).client_cmd
        assert "-groups" not in command and "--curves" not in command and "-I" not in command


def test_e8_uses_only_the_observed_default_c3_client_and_established_policy_controls():
    assert E8_SERVERS == ("openssl-S1", "openssl-S1-serverpref", "nss", "boringssl", "go")
    spec = e8_spec("openssl-S1", "botan", 1, Path("/tmp/v18-e8"))
    assert spec.condition == "openssl-S1--botan"
    assert "-groups" not in spec.client_cmd and "--curves" not in spec.client_cmd


def test_report_skips_the_non_run_inventory_json(tmp_path):
    (tmp_path / "v1.8-candidate-inventory.json").write_text("{}", encoding="utf-8")
    RunRecord("run", "openssl", "client-default-v18", 1, "botan", Metrics(None, False, False, "success"), True,
              provenance={"client": "botan", "server": "openssl-3.5.6-default", "classification": "C3",
                          "client_hello_groups": ["X25519MLKEM768"], "client_hello_key_shares": ["X25519"]}).to_json_path(tmp_path)
    assert "| botan -> openssl-3.5.6-default | C3 | X25519MLKEM768 | X25519 | 1 |" in render_v18(tmp_path)
