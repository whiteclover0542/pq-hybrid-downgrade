KYBER_GROUP_ID = 0x6399
HYBRID_GROUP_ID = 0x11EC
CLASSICAL_GROUP_ID = 0x001D
KYBER_PQ_BYTES = 1184
X25519_BYTES = 32
SNTRUP761_PQ_BYTES = 1158
SSH_HYBRID_KEX = b"sntrup761x25519-sha512@openssh.com"
SSH_CLASSICAL_KEX = b"curve25519-sha256"


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


def _hybrid_plus_classical_client_hello() -> bytes:
    supported_groups = HYBRID_GROUP_ID.to_bytes(2, "big") + CLASSICAL_GROUP_ID.to_bytes(2, "big")
    supported_groups_extension = (
        b"\x00\x0a"
        + (len(supported_groups) + 2).to_bytes(2, "big")
        + len(supported_groups).to_bytes(2, "big")
        + supported_groups
    )
    hybrid_share = (
        HYBRID_GROUP_ID.to_bytes(2, "big")
        + (KYBER_PQ_BYTES + X25519_BYTES).to_bytes(2, "big")
        + (b"\x22" * (KYBER_PQ_BYTES + X25519_BYTES))
    )
    classical_share = (
        CLASSICAL_GROUP_ID.to_bytes(2, "big")
        + X25519_BYTES.to_bytes(2, "big")
        + (b"\x11" * X25519_BYTES)
    )
    shares = hybrid_share + classical_share
    key_share_extension = (
        b"\x00\x33"
        + (len(shares) + 2).to_bytes(2, "big")
        + len(shares).to_bytes(2, "big")
        + shares
    )
    extensions = supported_groups_extension + key_share_extension
    body = b"\x03\x03" + (b"\x00" * 32) + b"\x00"
    body += b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return _tls_record(handshake)


def _ssh_packet(payload: bytes) -> bytes:
    padding = b"\x00" * 4
    packet_length = 1 + len(payload) + len(padding)
    return packet_length.to_bytes(4, "big") + bytes([len(padding)]) + payload + padding


def _ssh_kexinit_packet() -> bytes:
    kex_algorithms = SSH_HYBRID_KEX + b"," + SSH_CLASSICAL_KEX
    name_list = len(kex_algorithms).to_bytes(4, "big") + kex_algorithms
    payload = b"\x14" + (b"\x55" * 16) + name_list + (b"\x00\x00\x00\x00" * 9)
    payload += b"\x00" + b"\x00\x00\x00\x00"
    return _ssh_packet(payload)


SYNTHETIC_CLIENTHELLO = _client_hello_extension()
HYBRID_PLUS_CLASSICAL_CH = _hybrid_plus_classical_client_hello()
SYNTHETIC_SSH_KEX_ECDH_INIT = _ssh_packet(
    b"\x1e"
    + (SNTRUP761_PQ_BYTES + X25519_BYTES).to_bytes(4, "big")
    + (b"\x33" * SNTRUP761_PQ_BYTES)
    + (b"\x44" * X25519_BYTES)
)
SYNTHETIC_SSH_KEXINIT = _ssh_kexinit_packet()
