## Tier 1: Binding validation and high-level API safety tests.
## No network access required.

import unittest
import mbedtls
# Also import low-level modules directly for binding tests
import mbedtls/[ssl, net, entropy, ctr_drbg, x509_crt, error]

# -- Low-level binding validation -------------------------------------------

suite "ssl bindings":
  test "ssl context init and free":
    var ctx = create(SslContext)
    mbedtls_ssl_init(ctx)
    mbedtls_ssl_free(ctx)
    dealloc(ctx)

  test "ssl config init, defaults, and free":
    var conf = create(SslConfig)
    mbedtls_ssl_config_init(conf)
    let ret = mbedtls_ssl_config_defaults(conf,
      MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT)
    check ret == 0
    mbedtls_ssl_config_free(conf)
    dealloc(conf)

suite "net bindings":
  test "net context init and free":
    var ctx = create(NetContext)
    mbedtls_net_init(ctx)
    mbedtls_net_free(ctx)
    dealloc(ctx)

suite "entropy and ctr_drbg bindings":
  test "entropy init and free":
    var ctx = create(EntropyContext)
    mbedtls_entropy_init(ctx)
    mbedtls_entropy_free(ctx)
    dealloc(ctx)

  test "ctr_drbg seed and random generation":
    var ent = create(EntropyContext)
    var rng = create(CtrDrbgContext)
    mbedtls_entropy_init(ent)
    mbedtls_ctr_drbg_init(rng)
    let seedRet = mbedtls_ctr_drbg_seed(rng,
      mbedtls_entropy_func, ent, nil, 0)
    check seedRet == 0
    var buf: array[32, byte]
    let randRet = mbedtls_ctr_drbg_random(rng, addr buf[0], csize_t(buf.len))
    check randRet == 0
    var allZero = true
    for b in buf:
      if b != 0: allZero = false; break
    check not allZero
    mbedtls_ctr_drbg_free(rng)
    mbedtls_entropy_free(ent)
    dealloc(rng)
    dealloc(ent)

suite "x509 bindings":
  test "x509 crt init and free":
    var crt = create(X509Crt)
    mbedtls_x509_crt_init(crt)
    mbedtls_x509_crt_free(crt)
    dealloc(crt)

  test "x509 crt parse PEM buffer":
    const testCert = """-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUCY4D/OYUz3lVsMM7WM2c1VKrYu4wDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGdGVzdENBMB4XDTI2MDQwMTA1MjYwMFoXDTI3MDQwMTA1
MjYwMFowETEPMA0GA1UEAwwGdGVzdENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAuuwi7Ga2ogvEhhBOcd97X3M0IJp3Gd9L5JZX6VVgyPPNywOFAdY+
4WGRVUVTI5TeBlmMxsjq5dPyXrTmBPPH/SXaoi9IihMup8dGZjMPxUcrwNLl8XgC
aGPQaqCcpjKRikqGemY97lyTF548fTd08woQD0JRZcjL6gTbaEIhOsgdvUamZMLl
cFbdbk0ggl8SDxb6RzylQMmoWngLQxkAOHWRSXgqTY8dlRxADW3PgZRHt0UkMRG2
jy8AotZZfkdXe+UiczJjDTuuN7QxA46KKi1RsdoNutVCBztOVCWtG2fXNPAg6Zmv
lX6Avyo6aiB1erdh3T+/xAwz3Gz/YHytAwIDAQABo1MwUTAdBgNVHQ4EFgQU29vm
8wtCiX6i4Iqdyzq8C87C8LcwHwYDVR0jBBgwFoAU29vm8wtCiX6i4Iqdyzq8C87C
8LcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAezf/rmgPDsB4
EUw5ZaWVPFOzn4aNNFGAAT70G1rXPDmE6LNc5YrT5U1v++f4wK4SrU6phlt7j5oi
K/H9/0EIoxcT9ncPs2gsiPgeC0/tUAHeVXxU0TsKOEXtyG6nHHB1odpHhVWOgGhp
gvFAnfPgMjQC0lW+v/wtMU4wPFlaZLfEl3Z/mSSmuhpJrEKU47O8if7DtLhbRgFz
5MGTNBxJ7E+s5Qpkh82RvoYecy54qwFVClldTUoWfDR/xBfhh+gz6F4O31S5aKX6
gzeEO85Tr9AqT6a+GQwWZ69ZnSjXzKpZx+Eu0/X73WVPdXdTCK+siQ6WBfPMIsGV
+VIqqVuUOw==
-----END CERTIFICATE-----
"""
    var certBuf = testCert
    var crt = create(X509Crt)
    mbedtls_x509_crt_init(crt)
    let ret = mbedtls_x509_crt_parse(crt,
      cast[ptr byte](addr certBuf[0]), csize_t(certBuf.len + 1))
    check ret == 0
    mbedtls_x509_crt_free(crt)
    dealloc(crt)

suite "error bindings":
  test "strerror produces non-empty message":
    var buf: array[256, char]
    mbedtls_strerror(cint(MBEDTLS_ERR_SSL_WANT_READ), addr buf[0], csize_t(buf.len))
    let msg = $cast[cstring](addr buf[0])
    check msg.len > 0

# -- High-level API ----------------------------------------------------------

suite "TlsContext lifecycle":
  test "newTlsContext and explicit close":
    var ctx = newTlsContext(verify = false)
    check ctx.state == tsReady
    ctx.close()
    check ctx.state == tsClosed

  test "close is idempotent":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    ctx.close()
    check ctx.state == tsClosed

  test "destructor cleans up on scope exit":
    # No crash or leak — validated by running under valgrind/asan
    block:
      var ctx = newTlsContext(verify = false)
      check ctx.state == tsReady

  test "move transfers ownership":
    var a = newTlsContext(verify = false)
    var b = move(a)
    check b.state == tsReady
    check a.state == tsClosed  # moved-from is zeroed
    b.close()

  test "newTlsContext with bad caFile raises MbedTlsError":
    expect MbedTlsError:
      discard newTlsContext(caFile = "/nonexistent/path.pem")

suite "TlsContext state enforcement":
  test "write before connect raises MbedTlsError":
    var ctx = newTlsContext(verify = false)
    expect MbedTlsError:
      ctx.write("test")
    ctx.close()

  test "read before connect raises MbedTlsError":
    var ctx = newTlsContext(verify = false)
    expect MbedTlsError:
      discard ctx.read()
    ctx.close()

  test "connect on closed context raises MbedTlsError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    expect MbedTlsError:
      ctx.connect("example.com", 443)

  test "write on closed context raises MbedTlsError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    expect MbedTlsError:
      ctx.write("test")
