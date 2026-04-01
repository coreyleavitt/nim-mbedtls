# Testing

## Core principle

Every test must prove something specific. For a wrapper library, that means: does the Nim binding actually match the C function it claims to wrap? Does the high-level API handle the common cases correctly?

## Two test tiers

### Tier 1: Binding validation

Compile-time and basic runtime checks that verify the FFI bindings are correct. No network access required. Run on any host with mbedTLS development headers installed.

**What belongs here:**
- Compile-time `sizeof` checks for any non-opaque types
- Context init/free round-trips (allocate, initialize, free — no crash, no leak)
- Config defaults (verify `mbedtls_ssl_config_defaults` returns 0)
- RNG seeding (entropy init → ctr_drbg seed → generate random bytes)
- Certificate parsing from a PEM buffer (known-good cert embedded in test)
- Error code translation (known error code → correct human-readable string)

**Example:**
```nim
suite "binding validation":
  test "ssl context init and free":
    var ctx: SslContext
    mbedtls_ssl_init(addr ctx)
    mbedtls_ssl_free(addr ctx)
    # no crash = pass

  test "ctr_drbg produces random bytes":
    var entropy: EntropyContext
    var ctrDrbg: CtrDrbgContext
    mbedtls_entropy_init(addr entropy)
    mbedtls_ctr_drbg_init(addr ctrDrbg)
    let ret = mbedtls_ctr_drbg_seed(addr ctrDrbg, mbedtls_entropy_func,
                                      addr entropy, nil, 0)
    check ret == 0
    var buf: array[32, byte]
    let ret2 = mbedtls_ctr_drbg_random(addr ctrDrbg, addr buf[0], 32)
    check ret2 == 0
    check buf != default(array[32, byte])  # not all zeros
    mbedtls_ctr_drbg_free(addr ctrDrbg)
    mbedtls_entropy_free(addr entropy)
```

### Tier 2: Integration tests

Tests that establish real TLS connections. Require network access. These validate the full handshake/read/write path works end to end.

**What belongs here:**
- TLS 1.2 handshake against a known public server (e.g., `example.com:443`)
- TLS 1.3 handshake (if mbedTLS 3.x build supports it)
- HTTP GET over TLS and verify response starts with `HTTP/1.`
- Certificate verification failure (connect to expired cert, verify error)
- High-level API: `newTlsContext → connect → write → read → close` round-trip
- Custom BIO callbacks (verify low-level `mbedtls_ssl_set_bio` works with Nim closures)

**Not run in CI by default** — depends on network access and external server availability. Run manually or with a dedicated CI flag.

**Example:**
```nim
suite "tls client integration":
  test "HTTPS GET to example.com":
    var ctx = newTlsContext()
    ctx.connect("example.com", 443)
    ctx.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
    let response = ctx.read()
    check response.startsWith("HTTP/1.")
    ctx.close()
```

## What not to test

- Don't test mbedTLS itself (it has its own test suite)
- Don't test that `importc` works as a language feature
- Don't test error paths that require a malicious TLS server to trigger
- Don't test every mbedTLS config combination — test the defaults and the options this library explicitly exposes

## Test organization

```
tests/
  t_bindings.nim       -- Tier 1: init/free, RNG, cert parsing, error codes
  t_tls_client.nim     -- Tier 2: real TLS connections, HTTP over TLS
```

## CI requirements

- **Tier 1**: Linux host with `libmbedtls-dev` (or equivalent) installed. No network needed.
- **Tier 2**: Network access. Optional CI flag: `nimble test_integration`.

## Adding tests for new bindings

When wrapping a new mbedTLS module:
1. Add a Tier 1 test that inits and frees the context (proves the struct mapping is correct)
2. If the module has a self-contained operation (e.g., hashing, key generation), add a test with a known-answer vector
3. If the module requires a network or a peer, add a Tier 2 integration test
