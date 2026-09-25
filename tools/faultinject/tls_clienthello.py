from __future__ import annotations


TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SUPPORTED_GROUPS = 0x000A
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


def strip_hybrid(record: bytes, hybrid_group_id: int) -> bytes:
    extensions_start, extensions_end = _client_hello_extensions(record)
    extensions = bytearray()
    cursor = extensions_start
    changed = False

    while cursor < extensions_end:
        extension_type = _read_u16(record, cursor)
        extension_length = _read_u16(record, cursor + 2)
        extension_start = cursor + 4
        extension_end = extension_start + extension_length
        if extension_end > extensions_end:
            raise ValueError("truncated TLS extension")
        payload = record[extension_start:extension_end]

        if extension_type == TLS_SUPPORTED_GROUPS:
            if len(payload) < 2:
                raise ValueError("truncated supported_groups vector")
            groups_length = _read_u16(payload, 0)
            if groups_length != len(payload) - 2 or groups_length % 2:
                raise ValueError("invalid supported_groups vector length")
            groups = [payload[index : index + 2] for index in range(2, len(payload), 2)]
            retained_groups = [group for group in groups if int.from_bytes(group, "big") != hybrid_group_id]
            if len(retained_groups) != len(groups):
                payload = len(retained_groups * 2).to_bytes(2, "big") + b"".join(retained_groups)
                changed = True

        elif extension_type == TLS_KEY_SHARE:
            if len(payload) < 2:
                raise ValueError("truncated key_share vector")
            shares_length = _read_u16(payload, 0)
            if shares_length != len(payload) - 2:
                raise ValueError("invalid key_share vector length")
            share_cursor = 2
            retained_shares: list[bytes] = []
            while share_cursor < len(payload):
                group_id = _read_u16(payload, share_cursor)
                value_length = _read_u16(payload, share_cursor + 2)
                share_end = share_cursor + 4 + value_length
                if share_end > len(payload):
                    raise ValueError("truncated KeyShareEntry")
                if group_id != hybrid_group_id:
                    retained_shares.append(payload[share_cursor:share_end])
                else:
                    changed = True
                share_cursor = share_end
            payload = len(b"".join(retained_shares)).to_bytes(2, "big") + b"".join(retained_shares)

        extensions += extension_type.to_bytes(2, "big")
        extensions += len(payload).to_bytes(2, "big")
        extensions += payload
        cursor = extension_end

    if not changed:
        return record

    client_hello_prefix = record[9 : extensions_start - 2]
    client_hello = client_hello_prefix + len(extensions).to_bytes(2, "big") + extensions
    handshake = bytes([TLS_CLIENT_HELLO]) + len(client_hello).to_bytes(3, "big") + client_hello
    record_end = 5 + _read_u16(record, 3)
    return record[:3] + len(handshake).to_bytes(2, "big") + handshake + record[record_end:]


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
