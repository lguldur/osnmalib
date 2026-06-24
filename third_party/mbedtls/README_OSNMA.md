# Embedded Mbed TLS subset for OSNMA

This directory contains the source subset of **Mbed TLS 3.6.6** required by
`osnmalib`.

Enabled functionality:

- SHA-256
- SHA-512
- SHA3-256
- HMAC-SHA256 through `mbedtls_md_hmac()`
- AES-CMAC through `mbedtls_cipher_cmac()`
- ECDSA verification on secp256r1 and secp521r1

The configuration is in `include/mbedtls/mbedtls_config.h`.
It deliberately excludes TLS, X.509, RSA, entropy sources, random generators,
networking, file I/O, PSA Crypto and unused symmetric algorithms.

Implementation files compiled into `osnmalib`:

- aes.c
- asn1parse.c
- asn1write.c
- bignum.c
- bignum_core.c
- cipher.c
- cipher_wrap.c
- cmac.c
- constant_time.c
- ecdsa.c
- ecp.c
- ecp_curves.c
- md.c
- platform_util.c
- sha256.c
- sha3.c
- sha512.c

The full upstream copyright and license terms are retained in `LICENSE`.

## Header subset

The upstream header tree has also been reduced to the headers reached by the
OSNMA C++ translation units and the 17 selected Mbed TLS C translation units
with this fixed configuration. The retained list is recorded in
`HEADERS_OSNMA.txt`.

This package therefore does not provide the general Mbed TLS public API. If a
new primitive, curve, platform option, or Mbed TLS source file is enabled, its
additional header dependencies must be restored from the matching Mbed TLS
3.6.6 source release.
