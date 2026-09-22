from pathlib import Path
from faultinject.run import batch_specs


def test_batch_specs_count():
    specs = batch_specs(10, output_dir=Path("/tmp/p4"))
    assert len(specs) == 60                      # 6조합 × 10


def test_batch_specs_reps_are_complete_per_combo():
    specs = batch_specs(10, output_dir=Path("/tmp/p4"))
    reps = sorted(s.repetition for s in specs
                  if s.impl == "openssl" and s.fault_type == "group-list")
    assert reps == list(range(1, 11))            # r01..r10 정확히 한 번씩


def test_batch_specs_covers_six_combos():
    specs = batch_specs(1, output_dir=Path("/tmp/p4"))
    combos = {(s.impl, s.fault_type) for s in specs}
    assert len(combos) == 6
