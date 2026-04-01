# Design Philosophy

## Two layers: convenience and control

nim-mbedtls provides two complementary APIs:

1. **High-level API** (`mbedtls.nim`): Idiomatic Nim types and procs that handle the boilerplate — entropy setup, RNG seeding, config wiring, bio callbacks, resource cleanup. This is what most users should reach for. A TLS client connection should be a few lines, not a page of initialization ceremony.

2. **Low-level bindings** (`mbedtls/ssl.nim`, `mbedtls/net.nim`, etc.): Direct 1:1 `importc` mappings of every mbedTLS C function. Fully exposed, no restrictions. For users who need SNI configuration, custom verification callbacks, client certificates, DTLS, or anything else mbedTLS supports that the high-level API doesn't cover.

The high-level API is built entirely on top of the low-level bindings. Users can mix and match — start with the convenience layer and drop down to raw bindings when needed.

### Why not just the thin wrapper

A bare `importc` layer forces every consumer to reimplement the same 30-line context initialization sequence. That's not a wrapper — it's a header translation. The value of a Nim package is making the common case easy while keeping the uncommon case possible.

### Why not just the high-level API

mbedTLS has a large, nuanced API surface (client certs, custom BIO, DTLS, PSK, session resumption). Trying to wrap everything in a high-level abstraction would either leave features inaccessible or grow to match the complexity of the underlying library. Exposing the raw bindings gives power users an escape hatch without the library having to anticipate every use case.

## Flexible linking: dynamic or static

The default is dynamic linking against system `libmbedtls.so`, `libmbedx509.so`, and `libmbedcrypto.so`. Compile with `-d:mbedtlsStatic` to statically link instead.

- **Dynamic (default)**: Zero binary size cost when mbedTLS is already on the system (e.g., OpenWrt base packages). Automatically picks up system security patches.
- **Static (`-d:mbedtlsStatic`)**: Self-contained binary with no runtime dependency on system mbedTLS. Useful for non-OpenWrt targets, Docker containers, or environments where the system library version can't be controlled.

Both modes use the same API — the linking choice is invisible to application code.

## Zero runtime overhead

All FFI calls are direct `importc` bindings — no intermediate marshaling, no hidden allocations. A call to `mbedtls_ssl_handshake` in Nim compiles to the same machine code as calling it from C.

The `incompleteStruct` pragma is used for opaque types so Nim never tries to copy or sizeof mbedTLS's internal structures — they are always passed by pointer, matching the C API's ownership model.

## Resource safety

The high-level API uses Nim destructors (`=destroy`) to ensure mbedTLS contexts are freed when they go out of scope. No manual `free()` calls required. The low-level bindings do not manage lifetime — that's the caller's responsibility, same as in C.

## Scope boundary

nim-mbedtls wraps mbedTLS. It does not:

- Bundle CA certificates (use system CA store or provide your own)
- Implement certificate pinning policies (application concern)
- Manage connection pools or retries (application concern)
- Provide async I/O integration directly — but the low-level `mbedtls_ssl_set_bio` accepts custom send/recv callbacks, so consumers can wire in their own async transport

The library's job is to make mbedTLS usable from Nim. Everything above that belongs in the consuming application.
