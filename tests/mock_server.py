#!/usr/bin/env python3
"""Minimal TLS echo/HTTP server for fuzz testing nim-mbedtls.

Modes (determined by first bytes received):
- If data starts with "GET " or "POST ", respond with HTTP/1.0 200 echoing the body.
- Otherwise, echo the raw data back and close.

Usage: python3 fuzz_server.py <port> <certfile> <keyfile>
"""

import ssl, socket, sys, threading

def handle_client(conn, addr):
    try:
        data = conn.recv(65536)
        if not data:
            conn.close()
            return
        if data[:4] in (b"GET ", b"POST"):
            body = data.decode("utf-8", errors="replace")
            response = (
                f"HTTP/1.0 200 OK\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )
            conn.sendall(response.encode())
        else:
            conn.sendall(data)
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    finally:
        conn.close()

def main():
    port = int(sys.argv[1])
    certfile = sys.argv[2]
    keyfile = sys.argv[3]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(32)

    ssock = ctx.wrap_socket(sock, server_side=True)
    print(f"fuzz_server listening on 127.0.0.1:{port}", flush=True)

    while True:
        try:
            conn, addr = ssock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            pass

if __name__ == "__main__":
    main()
