from __future__ import annotations


SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEXINIT = 20
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


def _kexinit_algorithm_bounds(packet: bytes) -> tuple[int, int, int, int] | None:
    if len(packet) < 26:
        return None
    packet_length = int.from_bytes(packet[:4], "big")
    padding_length = packet[4]
    packet_end = 4 + packet_length
    payload_end = packet_end - padding_length
    if packet_end > len(packet) or payload_end < 26 or packet[5] != SSH_MSG_KEXINIT:
        return None
    algorithms_length = int.from_bytes(packet[22:26], "big")
    algorithms_start = 26
    algorithms_end = algorithms_start + algorithms_length
    if algorithms_end > payload_end:
        return None
    return algorithms_start, algorithms_end, payload_end, packet_end


def kexinit_algorithms(packet: bytes) -> list[str]:
    bounds = _kexinit_algorithm_bounds(packet)
    if bounds is None:
        raise ValueError("SSH KEXINIT packet not found")
    algorithms_start, algorithms_end, _, _ = bounds
    encoded = packet[algorithms_start:algorithms_end]
    return encoded.decode("ascii").split(",") if encoded else []


def strip_kexinit_algorithm(packet: bytes, algorithm: str) -> bytes:
    bounds = _kexinit_algorithm_bounds(packet)
    if bounds is None:
        raise ValueError("SSH KEXINIT packet not found")
    algorithms_start, algorithms_end, payload_end, packet_end = bounds
    retained = [name for name in kexinit_algorithms(packet) if name != algorithm]
    original = packet[algorithms_start:algorithms_end]
    replacement = ",".join(retained).encode("ascii")
    if replacement == original:
        return packet

    payload = packet[5:22] + len(replacement).to_bytes(4, "big") + replacement
    payload += packet[algorithms_end:payload_end]
    padding = packet[payload_end:packet_end]
    packet_length = 1 + len(payload) + len(padding)
    return packet_length.to_bytes(4, "big") + bytes([len(padding)]) + payload + padding
