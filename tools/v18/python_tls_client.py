import socket
import ssl
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: python_tls_client.py HOST PORT")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with socket.create_connection((sys.argv[1], int(sys.argv[2]))) as tcp:
    with context.wrap_socket(tcp, server_hostname=sys.argv[1]) as tls:
        print(f"TLS protocol: {tls.version()}")
