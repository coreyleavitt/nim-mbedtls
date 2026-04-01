## Low-level bindings for mbedtls_x509_crt_* functions.

type
  X509Crt* {.importc: "mbedtls_x509_crt", header: "<mbedtls/x509_crt.h>", incompleteStruct.} = object

proc mbedtls_x509_crt_init*(crt: ptr X509Crt) {.importc, header: "<mbedtls/x509_crt.h>".}
proc mbedtls_x509_crt_free*(crt: ptr X509Crt) {.importc, header: "<mbedtls/x509_crt.h>".}
proc mbedtls_x509_crt_parse_file*(crt: ptr X509Crt, path: cstring): cint {.importc, header: "<mbedtls/x509_crt.h>".}
proc mbedtls_x509_crt_parse_path*(crt: ptr X509Crt, path: cstring): cint {.importc, header: "<mbedtls/x509_crt.h>".}
proc mbedtls_x509_crt_parse*(crt: ptr X509Crt, buf: ptr byte, buflen: csize_t): cint {.importc, header: "<mbedtls/x509_crt.h>".}
