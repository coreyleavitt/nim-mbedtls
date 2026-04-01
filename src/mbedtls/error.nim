## Low-level bindings for mbedtls_strerror.

proc mbedtls_strerror*(ret: cint, buf: ptr char, buflen: csize_t) {.importc, header: "<mbedtls/error.h>".}
