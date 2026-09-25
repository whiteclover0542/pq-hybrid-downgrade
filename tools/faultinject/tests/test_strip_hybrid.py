from faultinject.tls_clienthello import _client_hello_extensions, find_key_share, strip_hybrid
from faultinject.tests.fixtures import HYBRID_PLUS_CLASSICAL_CH, HYBRID_GROUP_ID, CLASSICAL_GROUP_ID


def _supported_group_ids(record: bytes) -> list[int]:
    cursor, extensions_end = _client_hello_extensions(record)
    while cursor < extensions_end:
        extension_type = int.from_bytes(record[cursor : cursor + 2], "big")
        extension_length = int.from_bytes(record[cursor + 2 : cursor + 4], "big")
        extension_start = cursor + 4
        extension_end = extension_start + extension_length
        if extension_type == 0x000A:
            groups_length = int.from_bytes(record[extension_start : extension_start + 2], "big")
            groups = record[extension_start + 2 : extension_start + 2 + groups_length]
            return [int.from_bytes(groups[i : i + 2], "big") for i in range(0, len(groups), 2)]
        cursor = extension_end
    raise AssertionError("supported_groups extension missing")


def test_strip_removes_hybrid_keyshare_keeps_classical():
    out = strip_hybrid(HYBRID_PLUS_CLASSICAL_CH, HYBRID_GROUP_ID)
    key_share_ids = [g for (g, _, _) in find_key_share(out)]

    assert HYBRID_GROUP_ID not in key_share_ids
    assert CLASSICAL_GROUP_ID in key_share_ids
    assert HYBRID_GROUP_ID not in _supported_group_ids(out)
    assert CLASSICAL_GROUP_ID in _supported_group_ids(out)


def test_strip_shortens_record():
    out = strip_hybrid(HYBRID_PLUS_CLASSICAL_CH, HYBRID_GROUP_ID)

    assert len(out) < len(HYBRID_PLUS_CLASSICAL_CH)
    assert int.from_bytes(out[3:5], "big") == len(out) - 5
    assert int.from_bytes(out[6:9], "big") == len(out) - 9
