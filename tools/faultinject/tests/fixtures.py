KYBER_GROUP_ID = 0x6399
KYBER_PQ_BYTES = 1184
X25519_BYTES = 32
SNTRUP761_PQ_BYTES = 1158


def _tls_record(payload: bytes) -> bytes:
    return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload


def _client_hello_extension() -> bytes:
    key_share = (
        KYBER_GROUP_ID.to_bytes(2, "big")
        + (X25519_BYTES + KYBER_PQ_BYTES).to_bytes(2, "big")
        + (b"\x11" * X25519_BYTES)
        + (b"\x22" * KYBER_PQ_BYTES)
    )
    extension = b"\x00\x33" + (len(key_share) + 2).to_bytes(2, "big")
    extension += len(key_share).to_bytes(2, "big") + key_share
    body = b"\x03\x03" + (b"\x00" * 32) + b"\x00"
    body += b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return _tls_record(handshake)


def _ssh_packet(payload: bytes) -> bytes:
    padding = b"\x00" * 4
    packet_length = 1 + len(payload) + len(padding)
    return packet_length.to_bytes(4, "big") + bytes([len(padding)]) + payload + padding


SYNTHETIC_CLIENTHELLO = _client_hello_extension()
SYNTHETIC_SSH_KEX_ECDH_INIT = _ssh_packet(
    b"\x1e"
    + (SNTRUP761_PQ_BYTES + X25519_BYTES).to_bytes(4, "big")
    + (b"\x33" * SNTRUP761_PQ_BYTES)
    + (b"\x44" * X25519_BYTES)
)
