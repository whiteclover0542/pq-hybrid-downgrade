from __future__ import annotations


SSH_MSG_KEX_ECDH_INIT = 30
SNTRUP761_PUBLICKEY_BYTES = 1158
X25519_BYTES = 32


def find_kex_ecdh_init(packet: bytes) -> tuple[int, int] | None:
    if len(packet) < 10:
        return None
    packet_length = int.from_bytes(packet[:4], "big")
    padding_length = packet[4]
    packet_end = 4 + packet_length
    payload_end = packet_end - padding_length
    if packet_end > len(packet) or payload_end < 10 or packet[5] != SSH_MSG_KEX_ECDH_INIT:
        return None
    blob_length = int.from_bytes(packet[6:10], "big")
    blob_offset = 10
    if blob_offset + blob_length > payload_end:
        return None
    return blob_offset, blob_length


def forge_ssh_pq_component(packet: bytes) -> bytes:
    located = find_kex_ecdh_init(packet)
    if located is None:
        raise ValueError("SSH KEX_ECDH_INIT packet not found")
    blob_offset, blob_length = located
    if blob_length < SNTRUP761_PUBLICKEY_BYTES + X25519_BYTES:
        raise ValueError("SSH public-value blob is shorter than sntrup761x25519")

    forged = bytearray(packet)
    for index in range(blob_offset, blob_offset + SNTRUP761_PUBLICKEY_BYTES):
        forged[index] ^= 0xFF
    return bytes(forged)
