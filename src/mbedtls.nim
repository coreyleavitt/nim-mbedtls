## Nim wrapper for mbedTLS 3.x
##
## High-level TLS client API built on low-level importc bindings.
##
## .. code-block:: nim
##   var ctx = newTlsContext(caFile = "/etc/ssl/ca-bundle.pem")
##   ctx.connect("example.com", 443)
##   ctx.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
##   echo ctx.read()
##   ctx.close()
##
## Low-level access: ``import mbedtls/ssl``, ``mbedtls/net``, etc.
##
## **Thread safety:** ``TlsContext`` is not thread-safe. Each context must
## be used from a single thread. Sharing across threads is undefined behavior.

import mbedtls/[ssl, net, entropy, ctr_drbg, x509_crt, error]
export ssl, net, entropy, ctr_drbg, x509_crt, error

type
  MbedTlsError* = object of CatchableError
    code*: cint  ## mbedTLS negative error code

  TlsState* = enum
    tsClosed      ## Zero value — nothing allocated or already freed
    tsReady       ## Contexts initialized, ready to connect
    tsConnected   ## TLS session established, can read/write

  TlsContext* = object
    ## Owns all mbedTLS state for a single TLS client connection.
    ## Move-only: copying is a compile-time error. Not thread-safe.
    state: TlsState
    # Six heap-allocated sub-contexts. Separate allocations are required
    # because each is an incompleteStruct whose size is unknown to Nim;
    # they cannot be embedded or batched.
    ssl: ptr SslContext
    net: ptr NetContext
    entropy: ptr EntropyContext
    ctrDrbg: ptr CtrDrbgContext
    conf: ptr SslConfig
    cacert: ptr X509Crt

# -- Lifecycle hooks --------------------------------------------------------

proc `=destroy`*(ctx: TlsContext) =
  ## Free all mbedTLS resources. Sends close_notify if connected.
  ## Safe on zero-initialized, partially-initialized, and moved-from objects.
  ##
  ## Correctness argument: close_notify is only attempted when state is
  ## tsConnected, which is set only after a successful handshake.
  ## A failed connect leaves state as tsReady, so no close_notify is sent
  ## on a half-open TCP socket — mbedtls_net_free handles that cleanup.
  if ctx.state == tsConnected and ctx.ssl != nil:
    # Best-effort close_notify: retry on WANT_READ/WANT_WRITE up to 3 times.
    # Both can occur: WANT_WRITE when the outgoing alert stalls,
    # WANT_READ when waiting for the peer's close_notify acknowledgement.
    # In a destructor we cannot block indefinitely.
    var retries = 0
    while retries < 3:
      let ret = mbedtls_ssl_close_notify(ctx.ssl)
      if ret != MBEDTLS_ERR_SSL_WANT_WRITE and ret != MBEDTLS_ERR_SSL_WANT_READ:
        break
      inc retries
  # Free in reverse dependency order: ssl holds refs to conf and net,
  # so ssl_free must come first. Nil-checks handle every teardown scenario:
  # normal use, partial allocation (OOM), exception during init, moved-from.
  if ctx.ssl != nil:
    mbedtls_ssl_free(ctx.ssl); dealloc(ctx.ssl)
  if ctx.net != nil:
    mbedtls_net_free(ctx.net); dealloc(ctx.net)
  if ctx.cacert != nil:
    mbedtls_x509_crt_free(ctx.cacert); dealloc(ctx.cacert)
  if ctx.conf != nil:
    mbedtls_ssl_config_free(ctx.conf); dealloc(ctx.conf)
  if ctx.ctrDrbg != nil:
    mbedtls_ctr_drbg_free(ctx.ctrDrbg); dealloc(ctx.ctrDrbg)
  if ctx.entropy != nil:
    mbedtls_entropy_free(ctx.entropy); dealloc(ctx.entropy)

proc `=copy`*(dst: var TlsContext, src: TlsContext) {.error:
  "TlsContext cannot be copied; use 'move' to transfer ownership".}

# -- Error translation ------------------------------------------------------

proc checkRet(ret: cint) {.inline, raises: [MbedTlsError].} =
  ## Translate a negative mbedTLS return code into an exception.
  ## Inlined so the happy path (ret >= 0) compiles to a single branch.
  if ret < 0:
    var buf: array[256, char]
    mbedtls_strerror(ret, addr buf[0], csize_t(buf.len))
    let err = newException(MbedTlsError, $cast[cstring](addr buf[0]))
    err.code = ret
    raise err

proc raiseStateError(msg: string) {.noinline, noreturn, raises: [MbedTlsError].} =
  ## Raise MbedTlsError for state machine violations. Unlike doAssert,
  ## this is never compiled out — misuse is always caught, even with -d:danger.
  raise newException(MbedTlsError, msg)

# -- Public API --------------------------------------------------------------

proc state*(ctx: TlsContext): TlsState {.inline.} = ctx.state

proc close*(ctx: var TlsContext) =
  ## Send close_notify (if connected) and free all resources.
  ## Safe to call multiple times or on a never-connected context.
  `=destroy`(ctx)
  wasMoved(ctx)

proc newTlsContext*(caFile = "", caPath = "", verify = true): TlsContext
    {.raises: [MbedTlsError].} =
  ## Create a TLS client context. Initialises entropy, RNG, and SSL config.
  ##
  ## *caFile* — path to a PEM CA certificate file.
  ## *caPath* — path to a directory of PEM CA certificates.
  ## *verify* — require valid server certificate chain (default ``true``).
  ## When ``false``, uses ``MBEDTLS_SSL_VERIFY_NONE`` so that handshake
  ## succeeds regardless of certificate validity.
  ##
  ## If both *caFile* and *caPath* are empty and *verify* is ``true``,
  ## certificate verification will fail at handshake.
  ##
  ## Raises ``MbedTlsError`` if any mbedTLS call fails. On failure all
  ## partially-allocated resources are freed automatically via ``=destroy``
  ## on ``result``.

  # Heap-allocate each context (incompleteStruct — size unknown to Nim).
  # create() zeroes the memory, so mbedtls_*_free is safe even before _init.
  result.ssl = create(SslContext)
  result.net = create(NetContext)
  result.entropy = create(EntropyContext)
  result.ctrDrbg = create(CtrDrbgContext)
  result.conf = create(SslConfig)
  result.cacert = create(X509Crt)

  # _init calls never fail; after this =destroy can safely _free everything.
  mbedtls_ssl_init(result.ssl)
  mbedtls_net_init(result.net)
  mbedtls_entropy_init(result.entropy)
  mbedtls_ctr_drbg_init(result.ctrDrbg)
  mbedtls_ssl_config_init(result.conf)
  mbedtls_x509_crt_init(result.cacert)
  result.state = tsReady  # =destroy now knows there is work to do

  # Fallible operations — if checkRet raises, =destroy cleans up `result`.
  checkRet mbedtls_ctr_drbg_seed(result.ctrDrbg,
    mbedtls_entropy_func, result.entropy, nil, 0)
  checkRet mbedtls_ssl_config_defaults(result.conf,
    MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT)

  if caFile.len > 0:
    checkRet mbedtls_x509_crt_parse_file(result.cacert, caFile.cstring)
  elif caPath.len > 0:
    checkRet mbedtls_x509_crt_parse_path(result.cacert, caPath.cstring)

  mbedtls_ssl_conf_ca_chain(result.conf, result.cacert, nil)
  mbedtls_ssl_conf_rng(result.conf, mbedtls_ctr_drbg_random, result.ctrDrbg)
  if verify:
    mbedtls_ssl_conf_authmode(result.conf, MBEDTLS_SSL_VERIFY_REQUIRED)
  else:
    mbedtls_ssl_conf_authmode(result.conf, MBEDTLS_SSL_VERIFY_NONE)

  checkRet mbedtls_ssl_setup(result.ssl, result.conf)

proc connect*(ctx: var TlsContext, hostname: string, port: int)
    {.raises: [MbedTlsError].} =
  ## TCP connect + TLS handshake with SNI.
  ##
  ## Can only be called once on a freshly-created context.
  ## After a failed connect the context should be closed.
  if ctx.state != tsReady:
    raiseStateError("connect requires a fresh TlsContext (state is " & $ctx.state & ")")
  let portStr = $port
  checkRet mbedtls_ssl_set_hostname(ctx.ssl, hostname.cstring)
  checkRet mbedtls_net_connect(ctx.net, hostname.cstring,
    portStr.cstring, MBEDTLS_NET_PROTO_TCP)
  mbedtls_ssl_set_bio(ctx.ssl, ctx.net,
    mbedtls_net_send, mbedtls_net_recv, nil)
  # Handshake with WANT_READ/WANT_WRITE retry (required by mbedTLS for
  # non-blocking sockets; harmless for blocking sockets).
  var ret = mbedtls_ssl_handshake(ctx.ssl)
  while ret == MBEDTLS_ERR_SSL_WANT_READ or ret == MBEDTLS_ERR_SSL_WANT_WRITE:
    ret = mbedtls_ssl_handshake(ctx.ssl)
  checkRet ret
  ctx.state = tsConnected

proc write*(ctx: var TlsContext, data: string) {.raises: [MbedTlsError].} =
  ## Send *data* over the TLS channel. Handles partial writes internally.
  if ctx.state != tsConnected:
    raiseStateError("write requires an active connection (state is " & $ctx.state & ")")
  if data.len == 0: return
  var offset = 0
  while offset < data.len:
    let ret = mbedtls_ssl_write(ctx.ssl,
      cast[ptr byte](addr data[offset]), csize_t(data.len - offset))
    if ret == MBEDTLS_ERR_SSL_WANT_WRITE or ret == MBEDTLS_ERR_SSL_WANT_READ:
      continue
    checkRet ret
    offset += ret  # ret is guaranteed > 0 here: negatives raised, WANT_* retried

proc read*(ctx: var TlsContext, bufSize = 4096, maxSize = 8_388_608): string
    {.raises: [MbedTlsError].} =
  ## Read from the TLS channel until the peer sends close_notify or EOF.
  ##
  ## *bufSize* — initial buffer size (doubled as needed), clamped to *maxSize*.
  ## *maxSize* — upper bound on bytes read; raises ``MbedTlsError`` if
  ## exceeded. Pass ``int.high`` for unlimited.
  if ctx.state != tsConnected:
    raiseStateError("read requires an active connection (state is " & $ctx.state & ")")
  let initSize = max(1, min(bufSize, maxSize))
  result = newString(initSize)
  var pos = 0
  while true:
    if pos == result.len:
      let newLen = result.len * 2
      if newLen > maxSize:
        raise newException(MbedTlsError, "read exceeded maxSize of " & $maxSize & " bytes")
      result.setLen(newLen)
    let ret = mbedtls_ssl_read(ctx.ssl,
      cast[ptr byte](addr result[pos]), csize_t(result.len - pos))
    if ret == MBEDTLS_ERR_SSL_WANT_READ or ret == MBEDTLS_ERR_SSL_WANT_WRITE:
      continue
    if ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY or ret == 0: break
    checkRet ret
    pos += ret  # ret is guaranteed > 0 here: 0 breaks, negatives raised, WANT_* retried
  result.setLen(pos)
