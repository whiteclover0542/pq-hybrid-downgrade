import subprocess

from faultinject import harness
from faultinject.harness import ScenarioSpec, run_scenario


class _FakeServer:
    envs: list = []

    def __init__(self, command, env=None, **kwargs):
        _FakeServer.envs.append(env)

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


def _run(monkeypatch, tmp_path, server_env):
    _FakeServer.envs = []
    client_envs = []
    monkeypatch.setattr(harness.subprocess, "Popen", _FakeServer)
    monkeypatch.setattr(harness, "wait_for_listener", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        harness,
        "run_client",
        lambda command, env, timeout: client_envs.append(env) or subprocess.CompletedProcess(command, 1, "", ""),
    )
    spec = ScenarioSpec(
        impl="openssl", fault_type="server-setting", repetition=1, condition="3.5.6-S3",
        server_cmd=["server"], client_cmd=["client"], listen_port=8545,
        env={"WHO": "client"}, out_dir=tmp_path, server_env=server_env,
    )
    run_scenario(spec)
    return _FakeServer.envs, client_envs


def test_server_runs_with_its_own_environment(monkeypatch, tmp_path):
    server_envs, client_envs = _run(monkeypatch, tmp_path, {"WHO": "server"})

    assert server_envs == [{"WHO": "server"}]
    assert client_envs == [{"WHO": "client"}]


def test_server_defaults_to_the_shared_environment(monkeypatch, tmp_path):
    server_envs, _ = _run(monkeypatch, tmp_path, None)

    assert server_envs == [{"WHO": "client"}]
