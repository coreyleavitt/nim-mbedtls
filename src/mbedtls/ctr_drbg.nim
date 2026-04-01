## Low-level bindings for mbedtls_ctr_drbg_* functions.

type
  CtrDrbgContext* {.importc: "mbedtls_ctr_drbg_context", header: "<mbedtls/ctr_drbg.h>", incompleteStruct.} = object

proc mbedtls_ctr_drbg_init*(ctx: ptr CtrDrbgContext) {.importc, header: "<mbedtls/ctr_drbg.h>".}
proc mbedtls_ctr_drbg_free*(ctx: ptr CtrDrbgContext) {.importc, header: "<mbedtls/ctr_drbg.h>".}
proc mbedtls_ctr_drbg_seed*(ctx: ptr CtrDrbgContext, fEntropy: pointer, pEntropy: pointer, custom: ptr byte, len: csize_t): cint {.importc, header: "<mbedtls/ctr_drbg.h>".}
proc mbedtls_ctr_drbg_random*(pRng: pointer, output: ptr byte, outputLen: csize_t): cint {.importc, header: "<mbedtls/ctr_drbg.h>", cdecl.}
