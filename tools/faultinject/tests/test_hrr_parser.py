from faultinject.harness import detect_hrr, server_hello_is_hybrid, audit_flags_downgrade

HYBRID_SH = ">>> TLS 1.3, Handshake [length 0122], ClientHello\n" \
            "<<< TLS 1.3, Handshake [length 04ba], ServerHello\n"
CLASSICAL_SH = ">>> TLS 1.3, Handshake [length 0122], ClientHello\n" \
               "<<< TLS 1.3, Handshake [length 007a], ServerHello\n"
HRR_LOG = "<<< TLS 1.3, Handshake [length 0036], HelloRetryRequest\n"

def test_detect_hrr():
    assert detect_hrr(HRR_LOG) is True
    assert detect_hrr(CLASSICAL_SH) is False

def test_server_hello_size_discriminates_hybrid():
    assert server_hello_is_hybrid(HYBRID_SH) is True
    assert server_hello_is_hybrid(CLASSICAL_SH) is False
    assert server_hello_is_hybrid("no serverhello here") is None

def test_audit_flags_downgrade_is_silent():
    # advertised hybrid, negotiated classical -> downgrade happened, but audit does NOT auto-flag it
    assert audit_flags_downgrade(advertised_hybrid=True, negotiated_is_hybrid=False) is False
    assert audit_flags_downgrade(advertised_hybrid=False, negotiated_is_hybrid=False) is False
