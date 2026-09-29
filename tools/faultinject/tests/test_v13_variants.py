import subprocess
from pathlib import Path

from faultinject import analyze
from faultinject.analyze import EXPECTED_V12, EXPECTED_V13, comparison_v12, cve_verdict, expected_matrix
from faultinject.record import Metrics, RunRecord
from faultinject.v12 import VARIANT_SERVERS, preflight_v12, reported_version, v12_paths, v12_spec, v12_specs


def test_variant_servers_have_their_own_prefix_and_report_their_base_release():
    paths = v12_paths(VARIANT_SERVERS)

    assert paths["server_bin_3.5.6-revert"] == "/root/pq-hybrid-phase2/install/openssl-3.5.6-revert/bin/openssl"
    assert paths["server_bin_3.6.2"] == "/root/pq-hybrid-phase2/install/openssl-3.6.2/bin/openssl"
    assert paths["client_bin"] == "/root/pq-hybrid-phase2/install/openssl/bin/openssl"
    assert reported_version("3.5.5-cherrypick") == "3.5.5"
    assert reported_version("3.5.6-revert") == "3.5.6"
    assert reported_version("3.6.1") == "3.6.1"
    spec = v12_spec("3.5.6-revert", "S3", 1, Path("/tmp/v13"), paths)
    assert spec.server_env["LD_LIBRARY_PATH"] == "/root/pq-hybrid-phase2/install/openssl-3.5.6-revert/lib64"
    assert spec.env["LD_LIBRARY_PATH"] == "/root/pq-hybrid-phase2/install/openssl/lib64"
    assert spec.condition == "3.5.6-revert-S3"


def test_variant_matrix_is_four_servers_by_three_settings():
    specs = v12_specs(10, Path("/tmp/v13"), versions=VARIANT_SERVERS, paths=v12_paths(VARIANT_SERVERS))

    assert len(specs) == 120
    assert {spec.condition.rsplit("-", 1)[0] for spec in specs} == set(VARIANT_SERVERS)


def _runner(command, env=None, capture_output=True, text=True):
    if command[0] == "pgrep":
        return subprocess.CompletedProcess(command, 1, "", "")
    binary, kind = command[0], command[1]
    release = next(r for r in ("3.5.5", "3.5.6", "3.6.1", "3.6.2") if r in binary)
    if kind == "version":
        stdout = f"OpenSSL {release} 1 Jan 2026 (Library: OpenSSL {release} 1 Jan 2026)"
    else:
        stdout = "Providers:\n  default\n" if command[2] == "-providers" else "x25519:X25519MLKEM768"
    return subprocess.CompletedProcess(command, 0, stdout, "")


def test_preflight_checks_each_variant_against_its_base_release(tmp_path):
    paths = {}
    for key in ("client_bin", "cert", *(f"server_bin_{v}" for v in VARIANT_SERVERS)):
        target = tmp_path / key.replace("server_bin_", "openssl-")
        target.write_text("x")
        paths[key] = str(target)
    paths["client_bin"] = str(tmp_path / "openssl-3.5.5-client")
    Path(paths["client_bin"]).write_text("x")

    assert preflight_v12(paths, runner=_runner, port_free=lambda port: True) == (True, "ok")


def test_expected_matrices():
    assert EXPECTED_V12 == expected_matrix(("3.5.5",), ("3.5.6",))
    assert EXPECTED_V13[("3.5.6-revert", "S3")] == (False, "X25519")
    assert EXPECTED_V13[("3.6.1", "S3")] == (False, "X25519")
    assert EXPECTED_V13[("3.5.5-cherrypick", "S3")] == (True, "X25519MLKEM768")
    assert EXPECTED_V13[("3.6.2", "S3")] == (True, "X25519MLKEM768")
    assert EXPECTED_V13[("3.6.1", "S1")] == (False, "X25519")
    assert EXPECTED_V13[("3.6.1", "S2")] == (True, "X25519MLKEM768")
    assert len(EXPECTED_V13) == 12


def _write(run_dir, version, setting, rep, hrr, final):
    name = f"openssl_server-setting_r{rep:02d}_{version}-{setting}"
    names = {key: f"{name}{suffix}" for key, suffix in (
        ("pcap", ".pcapng"), ("client_log", "-client.log"), ("server_log", "-server.log"), ("capture_log", "-capture.log"))}
    for file_name in names.values():
        (run_dir / file_name).write_text("x", encoding="utf-8")
    RunRecord(
        name, "openssl", "server-setting", rep, f"{version}-{setting}",
        Metrics(final, final == "X25519MLKEM768", False, "success", hrr_pcap_present=hrr, hrr_log_present=hrr,
                server_hello_count=1, final_negotiated_group=final, client_precondition_verified=True),
        True, artifacts=names,
        provenance={"server_version": version, "server_setting": setting,
                    "server_bin_sha256": "s" * 64, "client_bin_sha256": "c" * 64},
    ).to_json_path(run_dir)


def test_v13_verdict_uses_the_variant_matrix(tmp_path, capsys):
    for (version, setting), (hrr, final) in EXPECTED_V13.items():
        for rep in range(1, 11):
            _write(tmp_path, version, setting, rep, hrr, final)

    assert cve_verdict(comparison_v12(tmp_path), expected=EXPECTED_V13) == (True, [])
    ok, reasons = cve_verdict(comparison_v12(tmp_path))
    assert ok is False and "3.5.5 S1: no records" in reasons

    assert analyze.main(["--v13", "--run-dir", str(tmp_path)]) == 0
    assert "Causal-isolation verdict: consistent" in capsys.readouterr().out


def test_analyze_modes_are_mutually_exclusive():
    import pytest

    with pytest.raises(SystemExit):
        analyze.main(["--v12", "--v13"])


def test_hybrid_first_client_advertises_hybrid_first_but_shares_x25519_only():
    from faultinject.v12 import HYBRID_FIRST_CLIENT_GROUPS, provenance_for

    paths = v12_paths()
    spec = v12_spec("3.5.5", "S1", 1, Path("/tmp/v14"), paths, client_groups=HYBRID_FIRST_CLIENT_GROUPS)

    assert HYBRID_FIRST_CLIENT_GROUPS == "X25519MLKEM768:*X25519"
    assert spec.client_cmd[-2:] == ["-groups", "X25519MLKEM768:*X25519"]
    assert provenance_for(spec, paths, {})["client_groups_arg"] == "X25519MLKEM768:*X25519"
    assert v12_specs(1, Path("/tmp/v14"), client_groups=HYBRID_FIRST_CLIENT_GROUPS)[0].client_cmd[-1] == "X25519MLKEM768:*X25519"


def test_v17_openssl36_variants_and_expected_split():
    from faultinject.analyze import EXPECTED_V17
    from faultinject.v12 import V36_VARIANT_SERVERS

    paths = v12_paths(V36_VARIANT_SERVERS)
    assert paths["server_bin_3.6.1-cherrypick"] == "/root/pq-hybrid-phase2/install/openssl-3.6.1-cherrypick/bin/openssl"
    assert reported_version("3.6.2-revert") == "3.6.2"
    assert EXPECTED_V17[("3.6.1-cherrypick", "S3")] == (True, "X25519MLKEM768")
    assert EXPECTED_V17[("3.6.2-revert", "S3")] == (False, "X25519")
    assert len(v12_specs(10, Path("/tmp/v17"), versions=V36_VARIANT_SERVERS, paths=paths)) == 60
