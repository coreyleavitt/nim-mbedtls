## libFuzzer harness: feed random bytes to mbedtls_x509_crt_parse.
## Tests the boundary between our Nim FFI bindings and mbedTLS's X.509 parser.
##
## Compile with:
##   nim c --cc:clang --noMain:on \
##     --passC:"-fsanitize=fuzzer-no-link,address" \
##     --passL:"-fsanitize=fuzzer,address" \
##     --path:src fuzz/fuzz_x509_parse.nim

import mbedtls/x509_crt

# x509_crt doesn't carry passL — add the libraries we need directly.
{.passL: "-lmbedx509 -lmbedcrypto".}

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(argc: ptr cint, argv: ptr cstringArray): cint {.exportc, cdecl.} =
  NimMain()
  return 0

proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint {.exportc, cdecl.} =
  if size == 0: return 0
  var crt = create(X509Crt)
  mbedtls_x509_crt_init(crt)
  # Try parsing as PEM (needs null terminator — won't have one, so will fail PEM
  # and fall through to DER parsing internally)
  discard mbedtls_x509_crt_parse(crt, data, size)
  mbedtls_x509_crt_free(crt)
  dealloc(crt)
  return 0
