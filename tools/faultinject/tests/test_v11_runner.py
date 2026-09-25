from pathlib import Path

from faultinject.run import v11_specs


def test_v11_covers_conditions():
    specs = v11_specs(1, output_dir=Path("/tmp/v11"))
    combos = {(spec.impl, spec.condition) for spec in specs}

    assert ("openssl", "silent-downgrade") in combos
    assert ("boringssl", "silent-downgrade") in combos
    assert ("openssh", "ssh-order") in combos
    assert ("openssl", "base") in combos
    assert ("openssh", "silent-downgrade") not in combos


def test_v11_repetitions_scale_each_valid_combination():
    one = len(v11_specs(1, output_dir=Path("/tmp/v11")))
    ten = len(v11_specs(10, output_dir=Path("/tmp/v11")))

    assert ten == one * 10
