# nim-mbedtls

Nim wrapper for [mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.x — TLS client/server bindings for embedded Linux.

## Status

**Scaffolded** — Low-level FFI bindings are declared, high-level API is stubbed. Not yet functional.

## Design

Two layers:

- **High-level** (`import mbedtls`): `TlsContext` with `connect`, `read`, `write`, `close`. Handles entropy, RNG, config wiring, and cleanup automatically.
- **Low-level** (`import mbedtls/ssl`, etc.): Direct 1:1 `importc` bindings for every mbedTLS C function. Full access to the underlying API.

## Linking

Dynamic linking by default (links against system `libmbedtls.so`). Use `-d:mbedtlsStatic` for static linking.

```bash
# Dynamic (default) — requires libmbedtls.so at runtime
nim c myapp.nim

# Static — requires libmbedtls.a at compile time
nim c -d:mbedtlsStatic myapp.nim
```

## Usage (planned)

```nim
import mbedtls

var ctx = newTlsContext()
ctx.connect("example.com", 443)
ctx.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
echo ctx.read()
ctx.close()
```

## Requirements

- Nim >= 2.0.0
- mbedTLS 3.x development headers and libraries

On OpenWrt: `opkg install libmbedtls-dev` (headers for build), `libmbedtls` is already in base packages (runtime).

On Tumbleweed: `zypper install mbedtls-devel`

## License

Apache-2.0
