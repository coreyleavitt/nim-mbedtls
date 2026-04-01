## Low-level bindings for mbedtls_net_* functions.

const MBEDTLS_NET_PROTO_TCP* = 0

type
  NetContext* {.importc: "mbedtls_net_context", header: "<mbedtls/net_sockets.h>", incompleteStruct.} = object

proc mbedtls_net_init*(ctx: ptr NetContext) {.importc, header: "<mbedtls/net_sockets.h>".}
proc mbedtls_net_free*(ctx: ptr NetContext) {.importc, header: "<mbedtls/net_sockets.h>".}
proc mbedtls_net_connect*(ctx: ptr NetContext, host, port: cstring, proto: cint): cint {.importc, header: "<mbedtls/net_sockets.h>".}
proc mbedtls_net_send*(ctx: pointer, buf: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/net_sockets.h>", cdecl.}
proc mbedtls_net_recv*(ctx: pointer, buf: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/net_sockets.h>", cdecl.}
