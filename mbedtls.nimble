# Package
version       = "1.0.0"
author        = "Corey Leavitt"
description   = "Nim wrapper for mbedTLS 3.x"
license       = "Apache-2.0"
srcDir        = "src"

# Dependencies
requires "nim >= 2.0.0"

task test, "Run binding validation tests (Tier 1, no network)":
  exec "nim c -r --path:src tests/t_bindings.nim"

task test_integration, "Run integration tests (Tier 2, requires network)":
  exec "nim c -r --path:src tests/t_tls_client.nim"

task test_stress, "Run randomized stress tests (requires Python + openssl)":
  exec "python3 tests/run_stress.py"

task fuzz, "Run coverage-guided fuzz tests (requires nim-fuzz Docker image)":
  exec "python3 fuzz/run_fuzz.py"
