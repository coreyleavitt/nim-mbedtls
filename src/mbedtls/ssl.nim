## Low-level bindings for mbedtls_ssl_* functions.

import mbedtls/x509_crt

{.passL: "-lmbedtls -lmbedx509 -lmbedcrypto".}

const
  MBEDTLS_SSL_IS_CLIENT* = 0
  MBEDTLS_SSL_IS_SERVER* = 1
  MBEDTLS_SSL_TRANSPORT_STREAM* = 0
  MBEDTLS_SSL_PRESET_DEFAULT* = 0
  MBEDTLS_SSL_VERIFY_NONE* = 0
  MBEDTLS_SSL_VERIFY_OPTIONAL* = 1
  MBEDTLS_SSL_VERIFY_REQUIRED* = 2
  MBEDTLS_ERR_SSL_WANT_READ* = -0x6900
  MBEDTLS_ERR_SSL_WANT_WRITE* = -0x6880
  MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY* = -0x7880

type
  SslContext* {.importc: "mbedtls_ssl_context", header: "<mbedtls/ssl.h>", incompleteStruct.} = object
  SslConfig* {.importc: "mbedtls_ssl_config", header: "<mbedtls/ssl.h>", incompleteStruct.} = object

proc mbedtls_ssl_init*(ssl: ptr SslContext) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_free*(ssl: ptr SslContext) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_setup*(ssl: ptr SslContext, conf: ptr SslConfig): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_set_hostname*(ssl: ptr SslContext, hostname: cstring): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_handshake*(ssl: ptr SslContext): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_write*(ssl: ptr SslContext, buf: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_read*(ssl: ptr SslContext, buf: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_close_notify*(ssl: ptr SslContext): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_get_verify_result*(ssl: ptr SslContext): uint32 {.importc, header: "<mbedtls/ssl.h>".}

proc mbedtls_ssl_config_init*(conf: ptr SslConfig) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_config_free*(conf: ptr SslConfig) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_config_defaults*(conf: ptr SslConfig, endpoint, transport, preset: cint): cint {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_conf_authmode*(conf: ptr SslConfig, authmode: cint) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_conf_ca_chain*(conf: ptr SslConfig, ca_chain: ptr X509Crt, ca_crl: pointer) {.importc, header: "<mbedtls/ssl.h>".}
proc mbedtls_ssl_conf_rng*(conf: ptr SslConfig, fRng: pointer, pRng: pointer) {.importc, header: "<mbedtls/ssl.h>".}

proc mbedtls_ssl_set_bio*(ssl: ptr SslContext, pCtx: pointer, fSend, fRecv, fRecvTimeout: pointer) {.importc, header: "<mbedtls/ssl.h>".}
