import subprocess
from pathlib import Path

from faultinject import v12
from faultinject.v12 import (
    CLIENT_GROUPS,
    native_environment,
    preflight_v12,
    v12_paths,
    v12_spec,
    v12_specs,
)


def test_only_the_server_binary_and_setting_change_across_versions():
    paths = v12_paths()
    old = v12_spec("3.5.5", "S3", 1, Path("/tmp/v12"), paths)
    new = v12_spec("3.5.6", "S3", 1, Path("/tmp/v12"), paths)

    assert old.client_cmd == new.client_cmd
    assert old.env == new.env
    assert old.client_cmd[0] == paths["client_bin"]
    assert old.server_cmd[0] == paths["server_bin_3.5.5"]
    assert new.server_cmd[0] == paths["server_bin_3.5.6"]
    assert new.server_env["LD_LIBRARY_PATH"] == "/root/pq-hybrid-phase2/install/openssl-3.5.6/lib64"
    assert new.condition == "3.5.6-S3"
    assert new.fault_type == "server-setting"
    assert new.capture_traffic is True


def test_server_group_settings():
    paths = v12_paths()
    command = lambda setting: v12_spec("3.5.5", setting, 1, Path("/tmp/v12"), paths).server_cmd

    assert command("S1")[-2:] == ["-groups", "X25519MLKEM768:X25519"]
    assert command("S2")[-2:] == ["-groups", "X25519MLKEM768/X25519"]
    assert command("S3")[-2:] == ["-groups", "DEFAULT"]
    assert "-groups" not in command("S4")


def test_client_is_native_only_and_offers_hybrid_with_an_x25519_share():
    spec = v12_spec("3.5.5", "S1", 1, Path("/tmp/v12"), v12_paths())

    assert spec.client_cmd[-2:] == ["-groups", CLIENT_GROUPS]
    assert "oqsprovider" not in spec.client_cmd + spec.server_cmd
    assert spec.env["OPENSSL_CONF"] == "/dev/null"
    assert "OPENSSL_MODULES" not in spec.env


def test_native_environment_replaces_library_path():
    environment = native_environment("3.5.6", {"LD_LIBRARY_PATH": "/old", "OPENSSL_MODULES": "/oqs"})

    assert environment["LD_LIBRARY_PATH"] == "/root/pq-hybrid-phase2/install/openssl-3.5.6/lib64"
    assert "OPENSSL_MODULES" not in environment


def test_required_matrix_is_sixty_runs_and_s4_is_opt_in():
    specs = v12_specs(10, output_dir=Path("/tmp/v12"))

    assert len(specs) == 60
    assert {spec.condition.split("-")[1] for spec in specs} == {"S1", "S2", "S3"}
    assert {spec.condition for spec in v12_specs(1, Path("/tmp/v12"), settings=("S4",))} == {"3.5.5-S4", "3.5.6-S4"}


def _runner(outputs):
    def run(command, env=None, capture_output=True, text=True):
        key = command[1] if command[1] != "list" else f"list{command[2]}"
        stdout = outputs(command[0], key)
        return subprocess.CompletedProcess(command, 0, stdout, "")
    return run


def _healthy(binary, key):
    version = "3.5.6" if "3.5.6" in binary else "3.5.5"
    return {
        "version": f"OpenSSL {version} 1 Jan 2026 (Library: OpenSSL {version} 1 Jan 2026)",
        "list-providers": "Providers:\n  default\n    name: OpenSSL Default Provider\n",
        "list-tls-groups": "secp256r1:x25519:X25519MLKEM768",
    }.get(key, "")


def _paths(tmp_path):
    paths = {}
    for key in ("client_bin", "server_bin_3.5.5", "server_bin_3.5.6", "cert"):
        name = key.replace("server_bin_", "openssl-") if key != "cert" else "server.pem"
        target = tmp_path / name
        target.write_text("x")
        paths[key] = str(target)
    return paths


def _preflight(tmp_path, outputs=_healthy, port_free=lambda port: True, residual=""):
    def runner(command, env=None, capture_output=True, text=True):
        if command[0] == "pgrep":
            return subprocess.CompletedProcess(command, 0 if residual else 1, residual, "")
        return _runner(outputs)(command, env, capture_output, text)
    return preflight_v12(_paths(tmp_path), runner=runner, port_free=port_free)


def test_preflight_accepts_a_healthy_environment(tmp_path):
    assert _preflight(tmp_path) == (True, "ok")


def test_preflight_rejects_a_server_that_reports_the_wrong_version(tmp_path):
    ok, reason = _preflight(tmp_path, outputs=lambda binary, key: _healthy(binary.replace("3.5.6", "3.5.5"), key))

    assert ok is False
    assert "3.5.6" in reason


def test_preflight_rejects_a_loaded_oqs_provider(tmp_path):
    ok, reason = _preflight(
        tmp_path,
        outputs=lambda binary, key: _healthy(binary, key) + ("\n  oqsprovider\n" if key == "list-providers" else ""),
    )

    assert ok is False
    assert "oqsprovider" in reason


def test_preflight_rejects_a_busy_port(tmp_path):
    ok, reason = _preflight(tmp_path, port_free=lambda port: port != 8545)

    assert ok is False
    assert "8545" in reason


def test_preflight_rejects_residual_processes(tmp_path):
    ok, reason = _preflight(tmp_path, residual="4242 /root/x/bin/openssl s_server -accept 8545\n")

    assert ok is False
    assert "s_server" in reason


def test_preflight_rejects_a_binary_running_on_another_versions_library(tmp_path):
    def mismatched_libs(binary, key):
        version = "3.5.6" if "3.5.6" in binary else "3.5.5"
        if key == "version":
            if "3.5.6" in binary:
                return "OpenSSL 3.5.6 1 Jan 2026 (Library: OpenSSL 3.5.5 1 Jan 2026)"
            return f"OpenSSL {version} 1 Jan 2026 (Library: OpenSSL {version} 1 Jan 2026)"
        return _healthy(binary, key)

    ok, reason = _preflight(tmp_path, outputs=mismatched_libs)

    assert ok is False
    assert "3.5.6" in reason


def test_preflight_rejects_a_version_string_without_the_library_clause(tmp_path):
    def no_library_clause(binary, key):
        if key == "version":
            version = "3.5.6" if "3.5.6" in binary else "3.5.5"
            return f"OpenSSL {version} 1 Jan 2026"
        return _healthy(binary, key)

    ok, reason = _preflight(tmp_path, outputs=no_library_clause)

    assert ok is False
