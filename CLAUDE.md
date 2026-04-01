# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Nim wrapper for mbedTLS 3.x. Two-layer design: low-level `importc` FFI bindings (`src/mbedtls/*.nim`) and a high-level convenience API (`src/mbedtls.nim`). Targets embedded Linux (OpenWrt) where mbedTLS is a base system package.

## Build & Test

Requires Nim >= 2.0.0 and mbedTLS 3.x development headers. Host is Windows; use the `nim-dev` Docker image for compilation:

```bash
# Build via container (dynamic linking, default)
docker run --rm -v "$PWD://work" -w //work nim-dev nim c src/mbedtls.nim

# Tier 1 tests (no network)
docker run --rm -v "$PWD://work" -w //work nim-dev nim c -r --path:src tests/t_bindings.nim

# Tier 2 integration tests (network required)
docker run --rm -v "$PWD://work" -w //work nim-dev nim c -r --path:src tests/t_tls_client.nim

# Nimble tasks
nimble test              # tier 1 (binding validation)
nimble test_integration  # tier 2 (real TLS connections)
```

The `nim-dev` image is `opensuse/tumbleweed` with `nim`, `mbedtls-devel`, `gcc`, and `ca-certificates-mozilla`. Rebuild with:
```bash
docker build -t nim-dev -f - . <<< 'FROM opensuse/tumbleweed
RUN zypper --non-interactive install nim mbedtls-devel gcc ca-certificates-mozilla
WORKDIR /work'
```

Install mbedTLS headers natively: `opkg install libmbedtls-dev` (OpenWrt), `zypper install mbedtls-devel` (Tumbleweed).

## Architecture

- `src/mbedtls.nim` — High-level `TlsContext` API: `newTlsContext`, `connect`, `read`, `write`, `close`. Owns all sub-contexts, uses `=destroy` for cleanup.
- `src/mbedtls/<module>.nim` — 1:1 `importc` bindings, one file per mbedTLS C header. Modules: `ssl`, `net`, `entropy`, `ctr_drbg`, `x509_crt`, `error`.
- `tests/t_bindings.nim` — Tier 1: init/free round-trips, RNG, cert parsing (offline).
- `tests/t_tls_client.nim` — Tier 2: real TLS connections (network required).

## FFI Conventions

- Opaque C structs use `{.importc, header: "...", incompleteStruct.}` — always passed by `ptr`, never copied or stack-allocated.
- Callback procs use `{.cdecl.}` calling convention.
- mbedTLS error codes are negative `cint` values. High-level API raises `MbedTlsError`.
- Linking flags (`-lmbedtls -lmbedx509 -lmbedcrypto`) are in `ssl.nim` via `{.passL.}`.

## Ownership & Safety (high-level API)

`TlsContext` is a move-only value type (Nim 2.x idiom):
- **`=copy` is disabled** — prevents aliased pointers / double-free. Use `move` to transfer.
- **`=destroy`** nil-checks each `ptr` field individually — safe for zero-initialized, partially-allocated, moved-from, and fully-initialized objects.
- **`close` = `=destroy` + `wasMoved`** — the stdlib pattern (same as `File`). Zeroes the object so the final scope-exit destroy is a no-op.
- **State machine** (`tsClosed` → `tsReady` → `tsConnected`) enforced by `raiseStateError` — misuse (write before connect, double-connect) raises `MbedTlsError`, never compiled out (unlike `doAssert`).
- **Exception-safe init** — `newTlsContext` allocates all contexts, calls infallible `_init` procs, sets `state = tsReady`, then runs fallible operations. If `checkRet` raises, `=destroy` on `result` cleans up.

Do not regress these invariants when modifying the high-level API.

## Adding New Bindings

Follow the existing pattern: one Nim file per mbedTLS header in `src/mbedtls/`, use `incompleteStruct` for opaque types, export the module from `src/mbedtls.nim`. Add a Tier 1 test (init/free at minimum) in `tests/t_bindings.nim`.
