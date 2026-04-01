## Tier 2: Integration tests — real TLS connections.
## Requires network access. Run with: nimble test_integration

import std/[strutils, os]
import unittest
import mbedtls

# System CA bundle paths (try common locations)
const caPaths = [
  "/etc/ssl/ca-bundle.pem",       # openSUSE / Tumbleweed
  "/etc/ssl/certs/ca-certificates.crt",  # Debian / Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt",   # RHEL / Fedora
  "/etc/ssl/cert.pem",            # Alpine / macOS
]

proc findCaFile(): string =
  for p in caPaths:
    if fileExists(p): return p
  raise newException(IOError, "no system CA bundle found; tried: " & $caPaths)

suite "tls client integration":
  let ca = findCaFile()

  test "HTTPS GET with real CA verification":
    var ctx = newTlsContext(caFile = ca)
    ctx.connect("www.google.com", 443)
    ctx.write("GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
    let response = ctx.read()
    check response.startsWith("HTTP/1.")
    ctx.close()

  test "destructor cleans up connected context":
    block:
      var ctx = newTlsContext(caFile = ca)
      ctx.connect("www.google.com", 443)

  test "close after connect is clean":
    var ctx = newTlsContext(caFile = ca)
    ctx.connect("www.google.com", 443)
    ctx.close()
    check ctx.state == tsClosed
    ctx.close()  # idempotent

  test "connect to bad host raises MbedTlsError":
    var ctx = newTlsContext(caFile = ca)
    expect MbedTlsError:
      ctx.connect("host.invalid.test", 443)
    ctx.close()

  test "verification failure without CA certs":
    var ctx = newTlsContext(verify = true)  # no CA loaded
    expect MbedTlsError:
      ctx.connect("www.google.com", 443)
    ctx.close()
