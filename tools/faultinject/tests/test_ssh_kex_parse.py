from faultinject.ssh_kexinit import (
    find_kex_ecdh_init,
    forge_ssh_pq_component,
    kexinit_algorithms,
    strip_kexinit_algorithm,
)
from faultinject.tests.fixtures import (
    SNTRUP761_PQ_BYTES,
    SSH_CLASSICAL_KEX,
    SSH_HYBRID_KEX,
    SYNTHETIC_SSH_KEX_ECDH_INIT,
    SYNTHETIC_SSH_KEXINIT,
)


def test_find_kex_ecdh_init_locates_client_public_blob():
    located = find_kex_ecdh_init(SYNTHETIC_SSH_KEX_ECDH_INIT)

    assert located is not None
    _, blob_length = located
    assert blob_length == SNTRUP761_PQ_BYTES + 32


def test_forge_ssh_preserves_length_and_keeps_x25519_component():
    before = SYNTHETIC_SSH_KEX_ECDH_INIT
    after = forge_ssh_pq_component(before)
    offset, blob_length = find_kex_ecdh_init(before)

    assert len(after) == len(before)
    assert before[:offset] == after[:offset]
    assert before[offset : offset + SNTRUP761_PQ_BYTES] != after[offset : offset + SNTRUP761_PQ_BYTES]
    assert before[offset + SNTRUP761_PQ_BYTES : offset + blob_length] == after[offset + SNTRUP761_PQ_BYTES : offset + blob_length]
    assert before[offset + blob_length :] == after[offset + blob_length :]


def test_strip_kexinit_removes_hybrid_algorithm_keeps_classical_algorithm():
    after = strip_kexinit_algorithm(SYNTHETIC_SSH_KEXINIT, SSH_HYBRID_KEX.decode())

    assert SSH_HYBRID_KEX.decode() not in kexinit_algorithms(after)
    assert SSH_CLASSICAL_KEX.decode() in kexinit_algorithms(after)
    assert len(after) < len(SYNTHETIC_SSH_KEXINIT)
    assert int.from_bytes(after[:4], "big") == len(after) - 4
