import subprocess
import sys
import textwrap


def test_run_client_closes_inherited_stdin_before_waiting_for_exit():
    """A detached parent keeps stdin open; the client must still receive EOF."""
    script = textwrap.dedent(
        """
        import sys
        from faultinject.harness import run_client

        result = run_client(
            [sys.executable, "-c", "import sys; sys.stdin.read(); print('closed')"],
            env=None,
            timeout=2,
        )
        print(result.stdout, end="")
        """
    )
    parent = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        return_code = parent.wait(timeout=3)
        stderr = parent.stderr.read()
        assert return_code == 0, stderr
        assert parent.stdout.read() == "closed\n"
        assert stderr == ""
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=3)
        if parent.stdin is not None:
            parent.stdin.close()
