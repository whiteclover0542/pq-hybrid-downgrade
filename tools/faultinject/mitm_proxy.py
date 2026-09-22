from __future__ import annotations

import select
import socket
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ProxyResult:
    mutated: bool
    client_to_server_bytes: int
    server_to_client_bytes: int


def run_proxy(
    listen_port: int,
    upstream_port: int,
    mutate: Callable[[bytes], bytes],
) -> ProxyResult:
    """Proxy one loopback connection and transform its first client payload only."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        client, _ = listener.accept()

        with client, socket.create_connection(("127.0.0.1", upstream_port), timeout=5) as upstream:
            first_payload = client.recv(16 * 1024)
            mutated = False
            client_to_server_bytes = 0
            server_to_client_bytes = 0
            if first_payload:
                forged = mutate(first_payload)
                if len(forged) != len(first_payload):
                    raise ValueError("mutation must preserve message length")
                upstream.sendall(forged)
                mutated = forged != first_payload
                client_to_server_bytes += len(forged)

            peers = {client: upstream, upstream: client}
            open_sockets = {client, upstream}
            while open_sockets:
                readable, _, _ = select.select(open_sockets, [], [], 5)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(16 * 1024)
                    target = peers[source]
                    if not data:
                        open_sockets.remove(source)
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    forwarded = data
                    if source is client and not mutated:
                        forwarded = mutate(data)
                        if len(forwarded) != len(data):
                            raise ValueError("mutation must preserve message length")
                        mutated = forwarded != data
                    target.sendall(forwarded)
                    if source is client:
                        client_to_server_bytes += len(forwarded)
                    else:
                        server_to_client_bytes += len(forwarded)

    return ProxyResult(mutated, client_to_server_bytes, server_to_client_bytes)
