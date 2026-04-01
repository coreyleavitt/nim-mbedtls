## Nim wrapper for mbedTLS 3.x
##
## Provides TLS client functionality by dynamically linking against
## system mbedTLS libraries (libmbedtls, libmbedcrypto, libmbedx509).
## Designed for OpenWrt where mbedTLS is a base package.

import mbedtls/[ssl, net, entropy, ctr_drbg, x509_crt]
export ssl, net, entropy, ctr_drbg, x509_crt
