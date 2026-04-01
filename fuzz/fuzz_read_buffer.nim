## libFuzzer harness: fuzz the read() buffer growth logic with mock ssl_read.
##
## The fuzzer input is interpreted as a stream of mock mbedtls_ssl_read return
## values that drive the buffer doubling, maxSize clamping, WANT_* retry, and
## close_notify detection paths in read().
##
## Compile with:
##   nim c --cc:clang --noMain:on \
##     --passC:"-fsanitize=fuzzer-no-link,address" \
##     --passL:"-fsanitize=fuzzer,address" \
##     --path:src fuzz/fuzz_read_buffer.nim

# We do NOT import mbedtls — this harness mocks everything to avoid linking
# mbedTLS and to control ssl_read return values precisely.

const
  WANT_READ = cint(-0x6900)
  WANT_WRITE = cint(-0x6880)
  PEER_CLOSE_NOTIFY = cint(-0x7880)

type
  MockSsl = object  # stand-in for SslContext
  FuzzStream = object
    data: ptr UncheckedArray[byte]
    size: int
    pos: int

var gStream: FuzzStream

proc mockSslRead(ssl: ptr MockSsl, buf: ptr byte, len: csize_t): cint =
  ## Consume a command byte from the fuzzer stream:
  ##   bits 0-1: action (0=data, 1=WANT_READ, 2=WANT_WRITE, 3=close_notify)
  ##   For action 0, next byte is payload length.
  if gStream.pos >= gStream.size:
    return 0  # EOF
  let cmd = gStream.data[gStream.pos]
  inc gStream.pos
  case cmd and 0x03
  of 0:  # return data
    if gStream.pos >= gStream.size: return 0
    var n = int(gStream.data[gStream.pos])
    inc gStream.pos
    if n == 0: n = 1  # at least 1 byte to make progress
    n = min(n, int(len))
    n = min(n, gStream.size - gStream.pos)
    if n <= 0: return 0
    copyMem(buf, addr gStream.data[gStream.pos], n)
    gStream.pos += n
    return cint(n)
  of 1: return WANT_READ
  of 2: return WANT_WRITE
  of 3: return PEER_CLOSE_NOTIFY
  else: return 0

proc readFuzz(bufSize, maxSize: int) =
  ## Duplicates the read() logic from src/mbedtls.nim with the mock ssl_read.
  ## We exercise the exact same buffer growth code path.
  var ssl: MockSsl
  let initSize = max(1, min(bufSize, maxSize))
  var result = newString(initSize)
  var pos = 0
  var wantRetries = 0
  const maxWantRetries = 10_000  # bound retries so fuzzer doesn't hang
  while true:
    if pos == result.len:
      let newLen = result.len * 2
      if newLen > maxSize:
        break  # maxSize exceeded — in real code this raises, here we just stop
      result.setLen(newLen)
    let ret = mockSslRead(addr ssl,
      cast[ptr byte](addr result[pos]), csize_t(result.len - pos))
    if ret == WANT_READ or ret == WANT_WRITE:
      inc wantRetries
      if wantRetries > maxWantRetries: break
      continue
    wantRetries = 0  # reset on non-WANT return
    if ret == PEER_CLOSE_NOTIFY or ret == 0: break
    if ret < 0: break  # error
    pos += ret
  result.setLen(pos)
  # result is discarded — we're testing for crashes/asan violations, not correctness

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(argc: ptr cint, argv: ptr cstringArray): cint {.exportc, cdecl.} =
  NimMain()
  return 0

proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint {.exportc, cdecl.} =
  if size < 4: return 0
  let d = cast[ptr UncheckedArray[byte]](data)
  # First 2 bytes: bufSize (1..4096)
  let bufSize = int(d[0]) * 16 + 1  # 1..4081
  # Next 2 bytes: maxSize (1..65536)
  let maxSize = (int(d[2]) shl 8 or int(d[3])) + 1  # 1..65536
  # Remaining bytes: mock ssl_read command stream
  gStream = FuzzStream(
    data: cast[ptr UncheckedArray[byte]](cast[int](data) + 4),
    size: int(size) - 4,
    pos: 0
  )
  readFuzz(bufSize, maxSize)
  return 0
