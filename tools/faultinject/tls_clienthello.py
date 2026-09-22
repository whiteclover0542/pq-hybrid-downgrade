from __future__ import annotations


TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_KEY_SHARE = 0x0033
X25519_BYTES = 32

# group_id: (PQ component offset within KeyShareEntry, PQ component length)
PQ_COMPONENTS = {
    0x11EC: (0, 1184),  # X25519MLKEM768: ML-KEM-768 || X25519
    0x6399: (X25519_BYTES, 1184),  # X25519Kyber768Draft00: X25519 || Kyber-768
}


def _read_u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValueError("truncated TLS field")
    return int.from_bytes(data[offset : offset + 2], "big")


def _client_hello_extensions(record: bytes) -> tuple[int, int]:
    if len(record) < 9 or record[0] != TLS_HANDSHAKE:
        raise ValueError("not a TLS handshake record")
    record_end = 5 + _read_u16(record, 3)
    if record_end > len(record) or record[5] != TLS_CLIENT_HELLO:
        raise ValueError("not a complete TLS ClientHello")
    handshake_end = 9 + int.from_bytes(record[6:9], "big")
    if handshake_end > record_end:
        raise ValueError("truncated ClientHello")

    cursor = 9 + 2 + 32
    if cursor >= handshake_end:
        raise ValueError("truncated ClientHello random")
    session_id_length = record[cursor]
    cursor += 1 + session_id_length
    cipher_suites_length = _read_u16(record, cursor)
    cursor += 2 + cipher_suites_length
    if cursor >= handshake_end:
        raise ValueError("truncated ClientHello compression methods")
    compression_length = record[cursor]
    cursor += 1 + compression_length
    extensions_length = _read_u16(record, cursor)
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end > handshake_end:
        raise ValueError("truncated ClientHello extensions")
    return cursor, extensions_end


def find_key_share(record: bytes) -> list[tuple[int, int, int]]:
    cursor, extensions_end = _client_hello_extensions(record)
    shares: list[tuple[int, int, int]] = []

    while cursor < extensions_end:
        extension_type = _read_u16(record, cursor)
        extension_length = _read_u16(record, cursor + 2)
        extension_start = cursor + 4
        extension_end = extension_start + extension_length
        if extension_end > extensions_end:
            raise ValueError("truncated TLS extension")
        if extension_type == TLS_KEY_SHARE:
            key_share_end = extension_start + 2 + _read_u16(record, extension_start)
            entry_cursor = extension_start + 2
            if key_share_end != extension_end:
                raise ValueError("invalid key_share vector length")
            while entry_cursor < key_share_end:
                group_id = _read_u16(record, entry_cursor)
                value_length = _read_u16(record, entry_cursor + 2)
                value_offset = entry_cursor + 4
                entry_cursor = value_offset + value_length
                if entry_cursor > key_share_end:
                    raise ValueError("truncated KeyShareEntry")
                shares.append((group_id, value_offset, value_length))
        cursor = extension_end
    return shares


def forge_pq_component(record: bytes, group_id: int) -> bytes:
    pq_offset, pq_length = PQ_COMPONENTS[group_id]
    target = next((share for share in find_key_share(record) if share[0] == group_id), None)
    if target is None:
        raise ValueError(f"key_share group 0x{group_id:04x} not found")
    _, value_offset, value_length = target
    if pq_offset + pq_length > value_length:
        raise ValueError("key_share is shorter than the fixed hybrid component boundary")

    forged = bytearray(record)
    start = value_offset + pq_offset
    for index in range(start, start + pq_length):
        forged[index] ^= 0xFF
    return bytes(forged)
