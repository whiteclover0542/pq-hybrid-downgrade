from pathlib import Path

from faultinject.harness import collect_metrics, parse_group


RAW = Path(__file__).resolve().parents[3] / "docs/research/baselines/raw"


def test_parse_openssl_baseline_group():
    log = (RAW / "openssl-67b5686b-baseline-client.log").read_text(errors="ignore")

    assert parse_group("openssl", log) == "X25519MLKEM768"


def test_parse_boringssl_baseline_group():
    log = (RAW / "boringssl-7fb4d3da-baseline-client.log").read_text(errors="ignore")

    assert parse_group("boringssl", log) == "X25519Kyber768Draft00"


def test_parse_openssh_baseline_group():
    log = (RAW / "openssh-d01efaa1-baseline-client.log").read_text(errors="ignore")

    assert parse_group("openssh", log) == "sntrup761x25519-sha512@openssh.com"


def test_baseline_is_hybrid_success():
    log = (RAW / "openssl-67b5686b-baseline-client.log").read_text(errors="ignore")

    metrics = collect_metrics("openssl", log, exit_code=0)

    assert metrics.is_hybrid is True
    assert metrics.handshake_result == "success"
    assert metrics.downgrade_visible is False
