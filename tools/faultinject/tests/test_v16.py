from pathlib import Path

from faultinject.record import Metrics, RunRecord
from faultinject.v16 import (
    DEFAULT_CLIENTS, REAL_SERVERS, direct_spec, render_v16, server_spec,
    survey_spec, v16_direct_specs, v16_specs,
)


def test_matrix_sizes():
    specs = v16_specs(3, Path("/tmp/v16"))

    assert len(specs) == 3 * len(DEFAULT_CLIENTS) + 3 * len(REAL_SERVERS) * 3
    assert {s.fault_type for s in specs} == {"client-default", "server-software"}


def test_direct_default_matrix_is_36_runs_and_uses_no_group_override():
    specs = v16_direct_specs(3, Path("/tmp/v16-direct"))

    assert len(specs) == 3 * len(REAL_SERVERS) * len(DEFAULT_CLIENTS)
    assert {s.fault_type for s in specs} == {"default-direct"}
    for spec in specs:
        assert "-groups" not in spec.client_cmd and "-curves" not in spec.client_cmd and "-I" not in spec.client_cmd
    assert direct_spec("caddy", "curl-system-openssl", 1, Path("/tmp/x")).capture_seconds == 10


def test_survey_clients_use_default_group_settings():
    for client in DEFAULT_CLIENTS:
        command = survey_spec(client, 1, Path("/tmp/v16")).client_cmd
        assert "-groups" not in command and "-curves" not in command and "-I" not in command, client


def test_non_openssl_clients_do_not_inherit_the_custom_openssl_library_path():
    assert "openssl/lib64" in survey_spec("openssl-3.5.5", 1, Path("/tmp/v16")).env["LD_LIBRARY_PATH"]
    assert "LD_LIBRARY_PATH" not in survey_spec("curl-system-openssl", 1, Path("/tmp/v16")).env


def test_server_software_runs_leave_group_settings_at_default():
    spec = server_spec("nginx", "C2", 1, Path("/tmp/v16"))

    assert spec.client_cmd[-1] == "X25519MLKEM768:*X25519"
    assert "LD_LIBRARY_PATH" not in spec.server_env
    assert spec.capture_seconds == 3
    assert server_spec("caddy", "C1", 1, Path("/tmp/v16")).capture_seconds == 10


def test_capture_window_is_configurable():
    from faultinject.harness import capture_command

    assert capture_command(Path("/tmp/x.pcapng"), 8545, 10)[capture_command(Path("/tmp/x.pcapng"), 8545, 10).index("-a") + 1] == "duration:10"


def test_render(tmp_path):
    RunRecord("a", "openssl", "client-default", 1, "go", Metrics(None, False, False, "success"), True,
              provenance={"part": "client-survey", "client": "go",
                          "client_hello_groups": ["X25519MLKEM768", "X25519"],
                          "client_hello_key_shares": ["X25519MLKEM768", "X25519"]}).to_json_path(tmp_path)
    RunRecord("b", "openssl", "server-software", 1, "nginx-C2",
              Metrics("X25519", False, False, "success", hrr_pcap_present=False, final_negotiated_group="X25519",
                      client_precondition_verified=True), True,
              provenance={"part": "server-software", "server": "nginx", "client": "C2"}).to_json_path(tmp_path)

    text = render_v16(tmp_path)

    assert "| go | X25519MLKEM768,X25519 | X25519MLKEM768,X25519 | 1 |" in text
    assert "| nginx | C2 | 1/1 | 0 | 0 | 1 | 0 |" in text
