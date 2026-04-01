## Randomized stress tests for nim-mbedtls high-level API.
## Requires a TLS echo server on localhost (started by run_stress.py).
##
## Compile-time config:
##   -d:stressPort=14433   TLS server port
##   -d:stressCert=<path>  CA cert for verification
##   -d:stressSeed=0       Random seed (0 = time-based)
##   -d:stressIters=50     Iterations per suite

import std/[random, strutils, times]
import unittest
import mbedtls

const
  StressPort {.intdefine: "stressPort".}: int = 14433
  StressCert {.strdefine: "stressCert".}: string = "/tmp/cert.pem"
  StressSeed {.intdefine: "stressSeed".}: int = 0
  StressIters {.intdefine: "stressIters".}: int = 50

var rng = if StressSeed == 0: initRand(getTime().toUnix) else: initRand(StressSeed)

proc randomString(r: var Rand, maxLen: int): string =
  let n = r.rand(maxLen)
  result = newString(n)
  for i in 0 ..< n:
    result[i] = char(r.rand(255))

proc httpGet(ctx: var TlsContext, path: string): string =
  ctx.write("GET " & path & " HTTP/1.0\r\nHost: localhost\r\n\r\n")
  result = ctx.read()

# -- State machine violation fuzzing (no server needed) ---------------------

suite "stress: state machine violations":
  test "random invalid operation sequences":
    for i in 0 ..< StressIters:
      var ctx = newTlsContext(verify = false)
      let op = rng.rand(3)
      case op
      of 0:  # write before connect
        expect MbedTlsError: ctx.write("data")
      of 1:  # read before connect
        expect MbedTlsError: discard ctx.read()
      of 2:  # double close then use
        ctx.close()
        ctx.close()  # idempotent
        expect MbedTlsError: ctx.write("data")
      of 3:  # connect on closed
        ctx.close()
        expect MbedTlsError: ctx.connect("localhost", StressPort)
      else: discard
      ctx.close()

  test "move then use moved-from":
    for i in 0 ..< StressIters:
      var a = newTlsContext(verify = false)
      var b = move(a)
      check a.state == tsClosed
      check b.state == tsReady
      # moved-from should reject all operations
      expect MbedTlsError: a.write("data")
      expect MbedTlsError: discard a.read()
      expect MbedTlsError: a.connect("localhost", StressPort)
      a.close()  # should be no-op
      b.close()

# -- Connected fuzzing (requires server) ------------------------------------

suite "stress: data sizes":
  test "random payload sizes survive write":
    for i in 0 ..< StressIters:
      let size = case rng.rand(5)
        of 0: 0
        of 1: 1
        of 2: rng.rand(128)
        of 3: rng.rand(4096)
        of 4: rng.rand(65536)
        else: rng.rand(256 * 1024)
      let payload = randomString(rng, size)

      var ctx = newTlsContext(caFile = StressCert)
      ctx.connect("localhost", StressPort)
      try:
        if payload.len > 0:
          ctx.write(payload)
      except MbedTlsError:
        discard  # server may reset on large raw payloads — that's fine
      ctx.close()

  test "HTTP round-trips with various sizes":
    for i in 0 ..< min(StressIters, 20):
      var ctx = newTlsContext(caFile = StressCert)
      ctx.connect("localhost", StressPort)
      let resp = httpGet(ctx, "/test")
      check resp.startsWith("HTTP/1.0 200")
      ctx.close()

suite "stress: buffer parameters":
  test "read with random bufSize and maxSize":
    for i in 0 ..< min(StressIters, 20):
      let bufSize = case rng.rand(4)
        of 0: 0
        of 1: 1
        of 2: rng.rand(64)
        of 3: rng.rand(8192)
        else: 4096
      let maxSize = case rng.rand(3)
        of 0: 1
        of 1: rng.rand(4096) + 1
        of 2: 8_388_608
        else: high(int)

      var ctx = newTlsContext(caFile = StressCert)
      ctx.connect("localhost", StressPort)
      ctx.write("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
      try:
        let resp = ctx.read(bufSize = bufSize, maxSize = maxSize)
        check resp.len > 0
      except MbedTlsError:
        discard  # maxSize exceeded is valid
      ctx.close()

suite "stress: rapid lifecycle":
  test "rapid connect/disconnect cycles":
    for i in 0 ..< StressIters:
      var ctx = newTlsContext(caFile = StressCert)
      ctx.connect("localhost", StressPort)
      ctx.close()

  test "create and destroy without connecting":
    for i in 0 ..< StressIters * 4:
      var ctx = newTlsContext(verify = false)
      ctx.close()

  test "destructor cleanup under scope churn":
    for i in 0 ..< StressIters * 4:
      block:
        var ctx = newTlsContext(verify = false)
        discard ctx.state

  test "error recovery: bad connect then good connect":
    for i in 0 ..< min(StressIters, 10):
      # Bad connect
      var bad = newTlsContext(caFile = StressCert)
      try:
        bad.connect("host.invalid.test", StressPort)
      except MbedTlsError:
        discard
      bad.close()
      # Good connect immediately after
      var good = newTlsContext(caFile = StressCert)
      good.connect("localhost", StressPort)
      good.write("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
      let resp = good.read()
      check resp.startsWith("HTTP/1.0 200")
      good.close()
