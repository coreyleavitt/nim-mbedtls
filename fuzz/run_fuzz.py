#!/usr/bin/env python3
"""Build and run libFuzzer harnesses for nim-mbedtls.

Intended to run inside the nim-fuzz Docker container.
Usage: python3 fuzz/run_fuzz.py [--timeout SECS] [--max-len BYTES]
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

FUZZ_DIR = Path(__file__).resolve().parent
PROJECT_DIR = FUZZ_DIR.parent
BIN_DIR = FUZZ_DIR / "bin"
CRASH_DIR = FUZZ_DIR / "crashes"

NIM_FLAGS = [
    "--cc:clang", "--noMain:on",
    "--passC:-fsanitize=fuzzer-no-link,address",
    "--passL:-fsanitize=fuzzer,address",
    f"--path:{PROJECT_DIR / 'src'}",
    "-d:release",
]

TARGETS = [
    {
        "name": "x509_parse",
        "source": FUZZ_DIR / "fuzz_x509_parse.nim",
        "corpus": FUZZ_DIR / "corpus_x509",
        "max_len": None,  # use global default
    },
    {
        "name": "read_buffer",
        "source": FUZZ_DIR / "fuzz_read_buffer.nim",
        "corpus": FUZZ_DIR / "corpus_read",
        "max_len": 4096,
    },
]


def generate_seeds():
    """Create seed corpus files for each target."""
    corpus_x509 = FUZZ_DIR / "corpus_x509"
    corpus_read = FUZZ_DIR / "corpus_read"
    corpus_x509.mkdir(exist_ok=True)
    corpus_read.mkdir(exist_ok=True)

    # x509: empty file + valid PEM cert
    (corpus_x509 / "seed_empty").write_bytes(b"")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", "/dev/null", "-out", str(corpus_x509 / "seed_pem"),
         "-days", "1", "-nodes", "-subj", "/CN=fuzz"],
        capture_output=True, check=True,
    )

    # read buffer: hand-crafted mock ssl_read command streams
    # Seed 1: bufSize=256, maxSize=8192, data(4 bytes), close_notify
    (corpus_read / "seed_basic").write_bytes(
        b"\x10\x00\x20\x00\x00\x04ABCD\x03"
    )
    # Seed 2: bufSize=1, maxSize=256, WANT_READ, WANT_WRITE, data(2 bytes)
    (corpus_read / "seed_retries").write_bytes(
        b"\x00\x00\x01\x00\x01\x02\x00\x02HI"
    )


def build(target: dict):
    """Compile a fuzz harness with Nim + clang + ASan + libFuzzer."""
    binary = BIN_DIR / f"fuzz_{target['name']}"
    cmd = ["nim", "c", *NIM_FLAGS, f"-o:{binary}", str(target["source"])]
    print(f"=== Building {target['name']} ===")
    subprocess.run(cmd, check=True)
    return binary


def run_target(target: dict, binary: Path, timeout: int, max_len: int) -> subprocess.Popen:
    """Launch a fuzzer process (non-blocking)."""
    effective_max_len = target["max_len"] or max_len
    log_file = FUZZ_DIR / f"log_{target['name']}.txt"
    cmd = [
        str(binary), str(target["corpus"]),
        f"-artifact_prefix={CRASH_DIR / target['name']}_",
        f"-max_total_time={timeout}",
        f"-max_len={effective_max_len}",
        "-print_final_stats=1",
    ]
    fh = open(log_file, "w")
    return subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT), fh, log_file


def print_summary(log_path: Path, name: str):
    """Print the last few lines of a fuzzer log."""
    print(f"\n=== {name} results ===")
    lines = log_path.read_text().splitlines()
    for line in lines[-6:]:
        print(f"  {line}")


def check_crashes() -> list[Path]:
    """Return list of crash/leak artifacts."""
    if not CRASH_DIR.exists():
        return []
    return [f for f in CRASH_DIR.iterdir() if f.is_file()]


def main():
    parser = argparse.ArgumentParser(description="Run nim-mbedtls fuzz harnesses")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("FUZZ_TIMEOUT", "60")),
                        help="Seconds per target (default: 60)")
    parser.add_argument("--max-len", type=int, default=int(os.environ.get("FUZZ_MAX_LEN", "65536")),
                        help="Max input size in bytes (default: 65536)")
    args = parser.parse_args()

    BIN_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    # Generate seed corpus
    generate_seeds()

    # Build all targets
    binaries = {}
    for target in TARGETS:
        binaries[target["name"]] = build(target)

    # Run all targets in parallel
    print(f"\n=== Fuzzing {len(TARGETS)} targets in parallel ({args.timeout}s each) ===\n")
    procs = []
    for target in TARGETS:
        proc, fh, log_path = run_target(target, binaries[target["name"]], args.timeout, args.max_len)
        procs.append((target, proc, fh, log_path))

    # Wait for all to finish
    for target, proc, fh, log_path in procs:
        proc.wait()
        fh.close()
        print_summary(log_path, target["name"])

    # Check for crashes
    crashes = check_crashes()
    if crashes:
        print(f"\n!!! CRASHES FOUND: {len(crashes)} artifacts in {CRASH_DIR}")
        for c in crashes:
            print(f"  {c}")
        sys.exit(1)

    print("\n=== Fuzzing complete — no crashes ===")


if __name__ == "__main__":
    main()
