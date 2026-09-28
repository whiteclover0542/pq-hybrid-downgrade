from pathlib import Path

import pytest

from faultinject import run
from faultinject.run import v11_specs


def test_v11_covers_conditions():
    specs = v11_specs(1, output_dir=Path("/tmp/v11"))
    combos = {(spec.impl, spec.condition) for spec in specs}

    assert ("openssl", "silent-downgrade") in combos
    assert ("boringssl", "silent-downgrade") in combos
    assert ("openssh", "ssh-order") in combos
    assert ("openssh", "onpath-strip") in combos
    assert ("openssl", "base") in combos
    assert ("openssh", "silent-downgrade") not in combos


def test_v11_repetitions_scale_each_valid_combination():
    one = len(v11_specs(1, output_dir=Path("/tmp/v11")))
    ten = len(v11_specs(10, output_dir=Path("/tmp/v11")))

    assert ten == one * 10


def test_v11_cli_preflights_before_running(monkeypatch):
    ran = []
    monkeypatch.setattr(run, "preflight", lambda *args: (True, "ok"))
    monkeypatch.setattr(
        run,
        "run_v11",
        lambda repetitions, output_dir=None: ran.append((repetitions, output_dir)) or [],
    )

    assert run.main(["--v11", "2"]) == 0
    assert ran == [(2, None)]


def test_v11_cli_routes_explicit_output_directory(monkeypatch, tmp_path):
    received = {}
    monkeypatch.setattr(run, "preflight", lambda *args: (True, "ok"))
    monkeypatch.setattr(
        run,
        "run_v11",
        lambda repetitions, output_dir=None: received.update(
            repetitions=repetitions, output_dir=output_dir
        ) or [],
    )

    assert run.main(["--v11", "2", "--output-dir", str(tmp_path)]) == 0
    assert received == {"repetitions": 2, "output_dir": tmp_path}


def test_output_directory_requires_v11_mode(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(run, "run_v11", lambda *args, **kwargs: pytest.fail("must not run"))

    with pytest.raises(SystemExit) as excinfo:
        run.main(["--output-dir", str(tmp_path)])

    assert excinfo.value.code == 2
    assert "--output-dir is only valid with --v11" in capsys.readouterr().err
