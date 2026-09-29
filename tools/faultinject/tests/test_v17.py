from pathlib import Path

from faultinject.v17 import BROWSERS, browser_spec, trace_audit, trace_spec, verbose_audit
from faultinject.v12 import v12_paths

# excerpts of a real 3.5.5 client -> 3.5.5 DEFAULT server -trace log (tr.sh probe, 2026-09-29)
TRACE = """Sent TLS Record
    ClientHello, Length=250
        extension_type=supported_groups(10), length=6
          ecdh_x25519 (29)
          X25519MLKEM768 (4588)
        extension_type=session_ticket(35), length=0
        extension_type=key_share(51), length=38
            NamedGroup: ecdh_x25519 (29)
Received TLS Record
    ServerHello, Length=118
        extension_type=key_share(51), length=36
            NamedGroup: ecdh_x25519 (29)
Received TLS Record
    EncryptedExtensions, Length=24
        extension_type=supported_groups(10), length=18
          X25519MLKEM768 (4588)
          ecdh_x25519 (29)
          secp256r1 (P-256) (23)

Received TLS Record
Peer Temp Key: X25519, 253 bits
"""

# excerpt of `tshark -V` on raw/v1.2 3.5.5-S3
VERBOSE = """            [Expert Info (Warning/Sequence): Connection reset (RST)]
            Handshake Type: Client Hello (1)
                    Supported Group: x25519 (0x001d)
                    Supported Group: X25519MLKEM768 (0x11ec)
                    Key Share Entry: Group: x25519, Key Exchange length: 32
            Handshake Type: Server Hello (2)
                    Key Share Entry: Group: x25519, Key Exchange length: 32
"""


def test_trace_audit_reads_both_group_lists_and_the_negotiated_group():
    result = trace_audit(TRACE)

    assert result["advertised_groups"] == ["ecdh_x25519", "X25519MLKEM768"]
    assert result["server_groups"] == ["X25519MLKEM768", "ecdh_x25519", "secp256r1 (P-256)"]
    assert result["negotiated_group"] == "X25519"
    assert result["single_output"] is True and result["explicit_warning"] is False


def test_verbose_audit_ignores_tcp_sequence_warnings():
    result = verbose_audit(VERBOSE)

    assert result["advertised_groups"] == ["x25519", "X25519MLKEM768"]
    assert result["negotiated_group"] == "x25519"
    assert result["single_output"] is True and result["explicit_warning"] is False


def test_specs():
    assert browser_spec("firefox", 1, Path("/tmp/v17")).capture_seconds == 30
    assert all(cmd[0] == "timeout" for cmd in BROWSERS.values())
    spec = trace_spec("3.5.5", "S3", 1, Path("/tmp/v17"), v12_paths(("3.5.5",)))
    assert "-trace" in spec.client_cmd and "-msg" not in spec.client_cmd


def test_trace_audit_reads_server_groups_from_encrypted_extensions_after_hrr():
    hrr = TRACE.replace("Received TLS Record\n    ServerHello", "Received TLS Record\n    ServerHello, Length=88\n"
                        "Sent TLS Record\n    ClientHello, Length=1400\n        extension_type=supported_groups(10), length=6\n"
                        "          ecdh_x25519 (29)\n          X25519MLKEM768 (4588)\nReceived TLS Record\n    ServerHello", 1)
    assert trace_audit(hrr)["server_groups"][0] == "X25519MLKEM768"


def test_grease_values_fold_into_one_label():
    from faultinject.v16 import _grease

    assert _grease(["0xbaba", "X25519MLKEM768"]) == "GREASE,X25519MLKEM768"
    assert _grease(["0x0a1a"]) == "0x0a1a"
