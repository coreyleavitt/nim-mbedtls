# Architecture

## Overview

nim-mbedtls is a two-layer Nim wrapper for mbedTLS 3.x: low-level FFI bindings and a high-level convenience API.

```
Application code
       |
  +----v----+
  | mbedtls |  High-level: TlsContext, TlsConfig, connect/read/write/close
  +----+----+
       |
  +----v-----------+
  | mbedtls/ssl    |  Low-level: 1:1 importc bindings
  | mbedtls/net    |
  | mbedtls/entropy|
  | mbedtls/ctr_drbg|
  | mbedtls/x509_crt|
  +----+-----------+
       |
  +----v-----------+
  | libmbedtls.so  |  System mbedTLS (dynamic) or static archive
  | libmbedcrypto  |
  | libmbedx509    |
  +----------------+
```

## Low-level bindings

### What we chose

Direct `importc` declarations matching mbedTLS 3.x headers. Each mbedTLS module maps to a Nim file:

| Nim module | mbedTLS header | Purpose |
|---|---|---|
| `mbedtls/ssl.nim` | `<mbedtls/ssl.h>` | SSL/TLS context, config, handshake, I/O |
| `mbedtls/net.nim` | `<mbedtls/net_sockets.h>` | TCP socket connect/send/recv |
| `mbedtls/entropy.nim` | `<mbedtls/entropy.h>` | Entropy collection for RNG |
| `mbedtls/ctr_drbg.nim` | `<mbedtls/ctr_drbg.h>` | Deterministic random bit generator |
| `mbedtls/x509_crt.nim` | `<mbedtls/x509_crt.h>` | X.509 certificate parsing and verification |

**Type mapping:**
- Opaque C structs → Nim objects with `{.importc, incompleteStruct.}` pragma (always used by pointer)
- C function pointers (callbacks) → Nim `proc` types with `{.cdecl.}` calling convention
- Error codes → `cint` return values (mbedTLS uses negative integers for errors)

### Why one file per mbedTLS module

mbedTLS organizes its API by header file. Mirroring that structure means:
- Users can import only what they need (`import mbedtls/ssl` without pulling in x509)
- Finding the Nim binding for a C function is trivial — same file name
- New mbedTLS modules can be added without touching existing files

### Why `incompleteStruct` instead of `bycopy`

mbedTLS context structs (`mbedtls_ssl_context`, `mbedtls_entropy_context`, etc.) are large and opaque. They must be allocated and passed by pointer — never copied. `incompleteStruct` tells Nim the struct's size is unknown, preventing accidental stack allocation or copying. All access goes through `ptr` types, matching the C API's contract.

## High-level API

### What we chose

A `TlsContext` object that owns all the mbedTLS state needed for a TLS client connection:

```nim
type
  TlsContext* = object
    ssl: SslContext
    net: NetContext
    entropy: EntropyContext
    ctrDrbg: CtrDrbgContext
    conf: SslConfig
    cacert: X509Crt
```

**Lifecycle:**
1. `newTlsContext()` — Initialize all sub-contexts, seed RNG, configure defaults
2. `connect(hostname, port)` — TCP connect + TLS handshake with SNI
3. `write(data)` / `read()` — Send and receive over the TLS channel
4. `close()` — Send close_notify, free all resources (also called by `=destroy`)

**Error handling:** mbedTLS functions return negative error codes. The high-level API translates these to Nim exceptions (`MbedTlsError`) with the error code and a human-readable message via `mbedtls_strerror`.

### Why ownership in a single object

The mbedTLS initialization sequence requires wiring multiple contexts together (entropy → ctr_drbg → ssl_config → ssl_context, plus bio callbacks pointing to net_context). Scattering these across separate variables is error-prone — the lifetimes are interdependent. Bundling them in one object ensures they're initialized together and freed in the correct order.

### Why destructors for cleanup

`=destroy` on `TlsContext` calls the `_free` functions in reverse initialization order. This prevents resource leaks when the context goes out of scope, even on exception paths. Users of the low-level API manage lifetime manually, same as in C.

## Linking strategy

### What we chose

Compile-time flag controls linking mode:

```nim
when defined(mbedtlsStatic):
  {.passL: "-lmbedtls -lmbedx509 -lmbedcrypto".}  # static archives
else:
  {.passL: "-lmbedtls -lmbedx509 -lmbedcrypto".}  # shared libraries (default)
```

For static linking, the consumer must have mbedTLS static libraries (`.a` files) in the library search path. For dynamic linking, the shared libraries must be available at runtime.

### Why not always static

On OpenWrt, mbedTLS is a base package — every device has `libmbedtls.so`. Dynamic linking adds zero bytes to the binary. Static linking would duplicate ~150 KB of code that's already on the device. For other platforms where mbedTLS isn't guaranteed, static linking is the right choice.

## Source structure

```
src/
  mbedtls.nim              -- high-level TlsContext API (convenience layer)
  mbedtls/
    ssl.nim                -- SSL/TLS context and config bindings
    net.nim                -- TCP socket bindings
    entropy.nim            -- entropy collection bindings
    ctr_drbg.nim           -- CSPRNG bindings
    x509_crt.nim           -- X.509 certificate bindings
docs/
  design-philosophy.md
  architecture.md
  testing.md
tests/
  t_bindings.nim           -- compile-time binding validation
  t_tls_client.nim         -- integration: TLS handshake against real server
```

## Future modules

mbedTLS has additional modules that may be wrapped as needed:

- `mbedtls/pk.h` — Public key (RSA, EC) operations (needed for client certificates)
- `mbedtls/debug.h` — Debug callback for TLS troubleshooting
- `mbedtls/error.h` — `mbedtls_strerror` for human-readable error messages
- `mbedtls/ssl_ticket.h` — Session ticket support (server-side)

These should follow the same pattern: one Nim file per mbedTLS header, `importc` with `incompleteStruct` for opaque types.
