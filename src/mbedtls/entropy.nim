## Low-level bindings for mbedtls_entropy_* functions.

type
  EntropyContext* {.importc: "mbedtls_entropy_context", header: "<mbedtls/entropy.h>", incompleteStruct.} = object

proc mbedtls_entropy_init*(ctx: ptr EntropyContext) {.importc, header: "<mbedtls/entropy.h>".}
proc mbedtls_entropy_free*(ctx: ptr EntropyContext) {.importc, header: "<mbedtls/entropy.h>".}
proc mbedtls_entropy_func*(data: pointer, output: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/entropy.h>", cdecl.}
