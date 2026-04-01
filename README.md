# nim-mbedtls

Nim wrapper for [mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.x — TLS client/server bindings for embedded Linux.

## Status

**Functional** — Low-level FFI bindings and high-level `TlsContext` API are implemented and tested.

## Design

Two layers:

- **High-level** (`import mbedtls`): `TlsContext` with `connect`, `read`, `write`, `close`. Handles entropy, RNG, config wiring, and cleanup automatically.
- **Low-level** (`import mbedtls/ssl`, etc.): Direct 1:1 `importc` bindings for every mbedTLS C function. Full access to the underlying API.

## Linking

Links against system mbedTLS libraries (`libmbedtls`, `libmbedx509`, `libmbedcrypto`). Dynamic by default; for static linking, ensure only static libraries (`.a` / `.lib`) are in your library search path.

## Usage

```nim
import mbedtls

var ctx = newTlsContext(caFile = "/etc/ssl/ca-bundle.pem")
ctx.connect("example.com", 443)
ctx.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
echo ctx.read()
ctx.close()
```

Skip certificate verification (development/testing only):

```nim
var ctx = newTlsContext(verify = false)
```

## Requirements

- Nim >= 2.0.0
- mbedTLS 3.x development headers and libraries

On OpenWrt: `opkg install libmbedtls-dev` (headers for build), `libmbedtls` is already in base packages (runtime).

On Tumbleweed: `zypper install mbedtls-devel`

## License

Apache-2.0
