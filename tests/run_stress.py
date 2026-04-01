#!/usr/bin/env python3
"""Orchestrate randomized stress tests for nim-mbedtls.

Generates a self-signed cert, starts a mock TLS server, compiles and runs
the stress test suite, then cleans up.

Usage: python3 tests/run_stress.py [--port PORT] [--iters N] [--seed N]
"""

import argparse
import atexit
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent

server_proc = None
cert_dir = None


def cleanup():
    global server_proc, cert_dir
    if server_proc and server_proc.poll() is None:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_proc.kill()
    if cert_dir:
        import shutil
        shutil.rmtree(cert_dir, ignore_errors=True)


def generate_cert(cert_dir: str) -> tuple[str, str]:
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", key, "-out", cert,
         "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        capture_output=True, check=True,
    )
    return cert, key


def start_server(port: int, cert: str, key: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(TESTS_DIR / "mock_server.py"), str(port), cert, key],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def wait_for_server(port: int, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return
        except OSError:
            time.sleep(0.1)
    print(f"ERROR: server not ready on port {port} after {timeout}s", file=sys.stderr)
    sys.exit(1)


def main():
    global server_proc, cert_dir

    parser = argparse.ArgumentParser(description="Run nim-mbedtls stress tests")
    parser.add_argument("--port", type=int, default=14433)
    parser.add_argument("--iters", type=int, default=50)
    parser.add_argument("--seed", type=int, default=0, help="0 = time-based")
    args = parser.parse_args()

    atexit.register(cleanup)

    # Generate self-signed cert
    cert_dir = tempfile.mkdtemp()
    cert, key = generate_cert(cert_dir)
    print(f"Generated cert: {cert}")

    # Start mock TLS server
    server_proc = start_server(args.port, cert, key)
    wait_for_server(args.port)
    print(f"Mock TLS server listening on 127.0.0.1:{args.port}")

    # Build and run stress tests
    nim_cmd = [
        "nim", "c", "-r", f"--path:{PROJECT_DIR / 'src'}",
        f"-d:stressPort={args.port}",
        f"-d:stressCert={cert}",
        f"-d:stressIters={args.iters}",
        f"-d:stressSeed={args.seed}",
        str(TESTS_DIR / "t_stress.nim"),
    ]
    print(f"Running: {' '.join(nim_cmd)}")
    result = subprocess.run(nim_cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
