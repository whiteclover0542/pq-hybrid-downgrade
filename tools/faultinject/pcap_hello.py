from __future__ import annotations

import re
from dataclasses import dataclass, field

from faultinject.tls_clienthello import (
    TLS_KEY_SHARE,
    TLS_SUPPORTED_GROUPS,
    _client_hello_extensions,
    _read_u16,
)

HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
GROUP_NAMES = {0x001D: "X25519", 0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00"}
_HANDSHAKE_RECORD = re.compile(rb"\x16\x03[\x01\x03]")


@dataclass
class HelloSummary:
    client_hellos: list[tuple[list[int], list[int]]] = field(default_factory=list)
    server_hellos: list[tuple[bool, int | None]] = field(default_factory=list)

    @property
    def hrr_count(self) -> int:
        return sum(is_hrr for is_hrr, _ in self.server_hellos)

    @property
    def server_hello_count(self) -> int:
        return sum(not is_hrr for is_hrr, _ in self.server_hellos)

    @property
    def final_group(self) -> int | None:
        real = [group for is_hrr, group in self.server_hellos if not is_hrr]
        return real[-1] if real else None


def group_name(code: int | None) -> str | None:
    if code is None:
        return None
    return GROUP_NAMES.get(code, f"0x{code:04x}")


def _extensions(data: bytes, start: int, end: int):
    cursor = start
    while cursor < end:
        ext_type = _read_u16(data, cursor)
        ext_len = _read_u16(data, cursor + 2)
        if cursor + 4 + ext_len > end:
            raise ValueError("truncated TLS extension")
        yield ext_type, data[cursor + 4 : cursor + 4 + ext_len]
        cursor += 4 + ext_len


def _client_hello(record: bytes) -> tuple[list[int], list[int]]:
    start, end = _client_hello_extensions(record)
    groups: list[int] = []
    shares: list[int] = []
    for ext_type, payload in _extensions(record, start, end):
        if ext_type == TLS_SUPPORTED_GROUPS:
            groups = [_read_u16(payload, index) for index in range(2, len(payload), 2)]
        elif ext_type == TLS_KEY_SHARE:
            cursor = 2
            while cursor < len(payload):
                shares.append(_read_u16(payload, cursor))
                cursor += 4 + _read_u16(payload, cursor + 2)
    return groups, shares


def _server_hello(record: bytes) -> tuple[bool, int | None]:
    record_end = 5 + _read_u16(record, 3)
    if record_end > len(record) or record[5] != 0x02 or record_end < 47:
        raise ValueError("not a complete ServerHello")
    random = record[11:43]
    cursor = 44 + record[43]  # skip legacy_session_id_echo
    cursor += 3  # cipher_suite, legacy_compression_method
    extensions_end = cursor + 2 + _read_u16(record, cursor)
    if extensions_end > record_end:
        raise ValueError("truncated ServerHello extensions")
    group = None
    for ext_type, payload in _extensions(record, cursor + 2, extensions_end):
        if ext_type == TLS_KEY_SHARE:
            group = _read_u16(payload, 0)
    return random == HRR_RANDOM, group


def summarize_hellos(capture: bytes) -> HelloSummary:
    # ponytail: scans raw pcapng bytes, so a Hello split across TCP segments is missed;
    # loopback MTU (65536) keeps every v1.2 Hello in one segment. Parse the frames if that changes.
    summary = HelloSummary()
    for match in _HANDSHAKE_RECORD.finditer(capture):
        record = capture[match.start() :]
        if len(record) < 6:
            continue
        try:
            if record[5] == 0x01:
                summary.client_hellos.append(_client_hello(record))
            elif record[5] == 0x02:
                summary.server_hellos.append(_server_hello(record))
        except ValueError:
            continue
    return summary


def client_precondition(summary: HelloSummary) -> bool:
    if not summary.client_hellos:
        return False
    groups, shares = summary.client_hellos[0]
    return {0x001D, 0x11EC} <= set(groups) and shares == [0x001D]
