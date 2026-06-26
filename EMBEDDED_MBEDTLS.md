# Embedded Mbed TLS integration

The OSNMA static library now contains the required subset of Mbed TLS 3.6.6.
No separate `mbedcrypto.vcxproj` build or link dependency is required.

## Location

`third_party/mbedtls/`

The upstream public headers are retained for compatibility, while only the 17
implementation files required by the OSNMA crypto calls are compiled.
The active minimal configuration is:

`third_party/mbedtls/include/mbedtls/mbedtls_config.h`

## Enabled primitives

- SHA-256
- SHA3-256
- SHA-512
- HMAC-SHA256
- AES-CMAC
- ECDSA verification on secp256r1 and secp521r1

## Visual Studio changes

- `osnmalib.vcxproj` compiles the selected Mbed TLS `.c` files directly.
- The embedded include and internal-header directories are configured for all
  project configurations.
- Each Mbed TLS implementation unit is explicitly compiled as C without a
  precompiled header.
- `osnma_test.vcxproj` no longer references the external
  `mbedcrypto.vcxproj` project.

## Validation performed

The embedded source tree was compiled independently on Linux with the same
minimal configuration. The following checks passed:

- complete OSNMA executable link using only the embedded Mbed TLS sources;
- all 17 OSNMA self-tests;
- known-answer tests for SHA-256, SHA3-256, SHA-512, HMAC-SHA256 and AES-CMAC;
- generated ECDSA verification tests for P-256/SHA-256 and P-521/SHA-512,
  with both compressed and uncompressed public keys.

The upstream Mbed TLS license is retained in `third_party/mbedtls/LICENSE`.
