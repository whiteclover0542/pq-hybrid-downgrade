from pathlib import Path

from faultinject.pcap_hello import (
    HRR_RANDOM,
    client_precondition,
    group_name,
    summarize_hellos,
)

RAW_V11 = Path(__file__).resolve().parents[3] / "docs/research/baselines/raw/v1.1"


def _summary(name: str):
    return summarize_hellos((RAW_V11 / f"{name}.pcapng").read_bytes())


def _server_hello(random: bytes, group: int) -> bytes:
    extension = (0x0033).to_bytes(2, "big") + (2).to_bytes(2, "big") + group.to_bytes(2, "big")
    body = b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00" + len(extension).to_bytes(2, "big") + extension
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_classical_server_hello_without_hrr():
    summary = _summary("openssl_condition_r01_silent-downgrade")

    assert summary.client_hellos[0] == ([0x001D, 0x11EC], [0x001D])
    assert summary.hrr_count == 0
    assert summary.server_hello_count == 1
    assert summary.final_group == 0x001D


def test_hrr_is_identified_by_its_fixed_random():
    summary = _summary("openssl_condition_r01_onpath-strip")

    assert summary.hrr_count == 1
    assert summary.server_hello_count == 1
    assert summary.final_group == 0x001D


def test_hybrid_server_hello():
    assert _summary("openssl_condition_r01_base").final_group == 0x11EC


def test_hrr_without_a_real_server_hello_has_no_final_group():
    summary = summarize_hellos(b"noise" + _server_hello(HRR_RANDOM, 0x11EC) + b"tail")

    assert summary.hrr_count == 1
    assert summary.server_hello_count == 0
    assert summary.final_group is None


def test_truncated_or_empty_capture_yields_an_empty_summary():
    for capture in (b"", b"\x16\x03\x03\x00", b"\x16\x03\x03\x00\x40\x02\x00"):
        summary = summarize_hellos(capture)
        assert summary.client_hellos == []
        assert summary.server_hellos == []
        assert summary.final_group is None


def test_client_precondition_requires_advertised_hybrid_and_a_single_x25519_share():
    assert client_precondition(_summary("openssl_condition_r01_silent-downgrade")) is True
    assert client_precondition(_summary("openssl_condition_r01_base")) is False
    assert client_precondition(_summary("boringssl_condition_r01_silent-downgrade")) is False
    assert client_precondition(summarize_hellos(b"")) is False


def test_group_name():
    assert group_name(0x001D) == "X25519"
    assert group_name(0x11EC) == "X25519MLKEM768"
    assert group_name(0x0017) == "0x0017"
    assert group_name(None) is None
