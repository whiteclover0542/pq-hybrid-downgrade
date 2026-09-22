from faultinject.tests.fixtures import KYBER_GROUP_ID, SYNTHETIC_CLIENTHELLO
from faultinject.tls_clienthello import find_key_share, forge_pq_component


def test_find_key_share_locates_hybrid_group():
    shares = find_key_share(SYNTHETIC_CLIENTHELLO)

    assert KYBER_GROUP_ID in [group_id for group_id, _, _ in shares]


def test_forge_preserves_length_and_changes_only_pq_target():
    before = SYNTHETIC_CLIENTHELLO
    after = forge_pq_component(before, KYBER_GROUP_ID)
    _, offset, length = next(share for share in find_key_share(before) if share[0] == KYBER_GROUP_ID)

    assert len(after) == len(before)
    assert after != before
    assert before[:offset] == after[:offset]
    assert before[offset : offset + 32] == after[offset : offset + 32]
    assert before[offset + 32 : offset + length] != after[offset + 32 : offset + length]
    assert before[offset + length :] == after[offset + length :]
