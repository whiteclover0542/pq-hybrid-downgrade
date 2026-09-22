from __future__ import annotations

import os


PHASE2_ROOT = "/root/pq-hybrid-phase2"


def phase2_paths() -> dict[str, str]:
    return {
        "openssl_bin": f"{PHASE2_ROOT}/install/openssl/bin/openssl",
        "openssl_cert": f"{PHASE2_ROOT}/openssl/apps/server.pem",
        "bssl_bin": f"{PHASE2_ROOT}/build/boringssl/tool/bssl",
        "boring_cert": f"{PHASE2_ROOT}/boring-cert.pem",
        "boring_key": f"{PHASE2_ROOT}/boring-key.pem",
        "ssh_bin": f"{PHASE2_ROOT}/openssh/ssh",
        "sshd_bin": f"{PHASE2_ROOT}/openssh/sshd",
        "sshd_config": f"{PHASE2_ROOT}/openssh-run/sshd_config",
        "ssh_key": f"{PHASE2_ROOT}/openssh-run/client_ed25519",
    }


def phase2_environment() -> dict[str, str]:
    environment = os.environ.copy()
    openssl_lib = f"{PHASE2_ROOT}/install/openssl/lib64"
    liboqs_lib = f"{PHASE2_ROOT}/install/liboqs/lib"
    existing = environment.get("LD_LIBRARY_PATH", "")
    environment["LD_LIBRARY_PATH"] = ":".join(
        value for value in (openssl_lib, liboqs_lib, existing) if value
    )
    environment["OPENSSL_MODULES"] = f"{openssl_lib}/ossl-modules"
    return environment
