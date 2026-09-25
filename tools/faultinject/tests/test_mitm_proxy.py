import socket
import threading

from faultinject.mitm_proxy import run_proxy


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_proxy_mutates_first_client_bytes_and_forwards_server_reply():
    upstream_port = _free_port()
    proxy_port = _free_port()
    received = []

    def upstream_server():
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", upstream_port))
            server.listen(1)
            connection, _ = server.accept()
            with connection:
                received.append(connection.recv(1024))
                connection.sendall(b"reply")

    upstream = threading.Thread(target=upstream_server)
    proxy_result = []
    proxy = threading.Thread(
        target=lambda: proxy_result.append(
            run_proxy(proxy_port, upstream_port, lambda data: data.replace(b"pq", b"PQ"))
        )
    )
    upstream.start()
    proxy.start()

    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
        client.sendall(b"hybrid-pq")
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1024) == b"reply"

    upstream.join(timeout=3)
    proxy.join(timeout=3)

    assert received == [b"hybrid-PQ"]
    assert proxy_result[0].mutated is True


def test_proxy_waits_for_first_matching_client_payload():
    upstream_port = _free_port()
    proxy_port = _free_port()
    received = []

    def upstream_server():
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", upstream_port))
            server.listen(1)
            connection, _ = server.accept()
            with connection:
                received.append(connection.recv(1024))
                connection.sendall(b"next")
                received.append(connection.recv(1024))
                connection.sendall(b"done")

    upstream = threading.Thread(target=upstream_server)
    proxy_result = []

    def mutate_if_kex(data: bytes) -> bytes:
        return data.replace(b"pq", b"PQ") if data.startswith(b"kex") else data

    proxy = threading.Thread(
        target=lambda: proxy_result.append(run_proxy(proxy_port, upstream_port, mutate_if_kex))
    )
    upstream.start()
    proxy.start()

    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
        client.sendall(b"init")
        assert client.recv(1024) == b"next"
        client.sendall(b"kex-pq")
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1024) == b"done"

    upstream.join(timeout=3)
    proxy.join(timeout=3)

    assert received == [b"init", b"kex-PQ"]
    assert proxy_result[0].mutated is True


def test_proxy_forwards_a_length_changing_tls_record_mutation():
    upstream_port = _free_port()
    proxy_port = _free_port()
    received = []

    def upstream_server():
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", upstream_port))
            server.listen(1)
            connection, _ = server.accept()
            with connection:
                received.append(connection.recv(1024))
                connection.sendall(b"reply")

    upstream = threading.Thread(target=upstream_server)
    proxy_result = []
    proxy = threading.Thread(
        target=lambda: proxy_result.append(
            run_proxy(proxy_port, upstream_port, lambda data: data.replace(b"-pq", b""))
        )
    )
    upstream.start()
    proxy.start()

    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
        client.sendall(b"hybrid-pq")
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1024) == b"reply"

    upstream.join(timeout=3)
    proxy.join(timeout=3)

    assert received == [b"hybrid"]
    assert proxy_result[0].mutated is True
