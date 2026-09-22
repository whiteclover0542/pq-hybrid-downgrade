from pathlib import Path
import socket

from faultinject.harness import (
    capture_command,
    collect_metrics,
    parse_group,
    wait_for_listener,
)


RAW = Path(__file__).resolve().parents[3] / "docs/research/baselines/raw"


def test_parse_openssl_baseline_group():
    log = (RAW / "openssl-67b5686b-baseline-client.log").read_text(errors="ignore")

    assert parse_group("openssl", log) == "X25519MLKEM768"


def test_parse_openssl_group_from_s_client_state_output():
    log = "Peer Temp Key: X25519, 253 bits\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nDONE\n"

    metrics = collect_metrics("openssl", log, exit_code=0)

    assert metrics.negotiated_group == "X25519"
    assert metrics.handshake_result == "success"
    assert metrics.downgrade_visible is True


def test_parse_openssl_null_group_as_no_negotiated_group():
    metrics = collect_metrics("openssl", "Negotiated TLS1.3 group: <NULL>\n", exit_code=1)

    assert metrics.negotiated_group is None
    assert metrics.downgrade_visible is False


def test_parse_boringssl_baseline_group():
    log = (RAW / "boringssl-7fb4d3da-baseline-client.log").read_text(errors="ignore")

    assert parse_group("boringssl", log) == "X25519Kyber768Draft00"


def test_parse_openssh_baseline_group():
    log = (RAW / "openssh-d01efaa1-baseline-client.log").read_text(errors="ignore")

    assert parse_group("openssh", log) == "sntrup761x25519-sha512@openssh.com"


def test_baseline_is_hybrid_success():
    log = (RAW / "openssl-67b5686b-baseline-client.log").read_text(errors="ignore")

    metrics = collect_metrics("openssl", log, exit_code=0)

    assert metrics.is_hybrid is True
    assert metrics.handshake_result == "success"
    assert metrics.downgrade_visible is False


def test_wait_for_listener_retries_until_the_server_accepts_connections(monkeypatch):
    attempts = []

    class Connection:
        def close(self):
            pass

    def create_connection(address, timeout):
        attempts.append((address, timeout))
        if len(attempts) == 1:
            raise ConnectionRefusedError
        return Connection()

    monkeypatch.setattr(socket, "create_connection", create_connection)

    wait_for_listener("127.0.0.1", 8443, timeout=1, retry_interval=0)

    assert len(attempts) == 2


def test_capture_command_is_limited_to_the_loopback_listener_port(tmp_path):
    command = capture_command(tmp_path / "run.pcapng", 8443)

    assert command[:3] == ["tshark", "-i", "lo"]
    assert "-l" in command
    assert command[command.index("-a") + 1] == "duration:3"
    assert "tcp port 8443" in command
    assert str(tmp_path / "run.pcapng") in command
