from pathlib import Path

from faultinject import v15
from faultinject.pcap_hello import HelloSummary
from faultinject.record import Metrics, RunRecord
from faultinject.v15 import CLIENTS, SERVERS, client_precondition_v15, comparison_v15, render_v15, v15_specs


def test_matrix_covers_every_server_and_client():
    specs = v15_specs(5, Path("/tmp/v15"))

    assert len(specs) == len(SERVERS) * len(CLIENTS) * 5 == 105
    assert {spec.condition for spec in specs} == {f"{s}-{c}" for s in SERVERS for c in CLIENTS}


def test_matrix_can_select_one_server():
    specs = v15_specs(3, Path("/tmp/v15"), servers=("boringssl",))

    assert len(specs) == 9
    assert {spec.condition.rsplit("-", 1)[0] for spec in specs} == {"boringssl"}


def test_server_commands_list_the_hybrid_first():
    commands = {name: " ".join(v15.server_command(name)) for name in SERVERS}

    assert "-groups X25519MLKEM768:X25519" in commands["openssl-S1"]
    assert "-groups X25519MLKEM768/X25519" in commands["openssl-S2"]
    assert "-serverpref" in commands["openssl-S1-serverpref"]
    assert "-curves X25519MLKEM768:X25519" in commands["boringssl"]
    assert "-groups X25519MLKEM768,X25519" in commands["go"]
    assert "-I x25519mlkem768,x25519" in commands["nss"]
    assert commands["rustls"].endswith("X25519MLKEM768,X25519")


def test_clients_differ_only_in_group_argument():
    specs = {spec.condition.rsplit("-", 1)[1]: spec for spec in v15_specs(1, Path("/tmp/v15")) if spec.condition.startswith("go-")}

    assert specs["C1"].client_cmd[-1] == "X25519MLKEM768:X25519"
    assert specs["C2"].client_cmd[-1] == "X25519MLKEM768:*X25519"
    assert specs["C3"].client_cmd[-1] == "X25519:X25519MLKEM768"
    assert specs["C1"].client_cmd[:-1] == specs["C3"].client_cmd[:-1]


def test_precondition_checks_order_and_shares():
    c2 = HelloSummary(client_hellos=[([0x11EC, 0x001D], [0x001D])])
    c3 = HelloSummary(client_hellos=[([0x001D, 0x11EC], [0x001D])])

    assert client_precondition_v15(c2, "C2") is True
    assert client_precondition_v15(c3, "C2") is False
    assert client_precondition_v15(c3, "C3") is True
    assert client_precondition_v15(HelloSummary(), "C1") is False


def _write(run_dir, server, client, rep, hrr, final):
    name = f"tls_negotiation-function_r{rep:02d}_{server}-{client}"
    RunRecord(
        name, "tls", "negotiation-function", rep, f"{server}-{client}",
        Metrics(final, final == "X25519MLKEM768", False, "success", detail="handshake-completed",
                hrr_pcap_present=hrr, final_negotiated_group=final, client_precondition_verified=True),
        True, provenance={"server": server, "client": client},
    ).to_json_path(run_dir)


def test_comparison_and_report(tmp_path):
    for rep in range(1, 6):
        _write(tmp_path, "go", "C2", rep, False, "X25519")
    counts = comparison_v15(tmp_path)

    assert counts[("go", "C2")]["n"] == 5
    assert counts[("go", "C2")]["classical"] == 5
    assert counts[("go", "C2")]["completed"] == 5
    assert "| go | C2 | 5/5 | 5 | 5 | 0 | 0 | 5 | 0 |" in render_v15(tmp_path)
