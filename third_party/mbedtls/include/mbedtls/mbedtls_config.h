/**
 * Minimal Mbed TLS 3.6.6 configuration for the OSNMA library.
 *
 * Enabled primitives:
 * - SHA-256, SHA-512, SHA3-256
 * - HMAC-SHA256 through the generic message-digest API
 * - AES-CMAC through the generic cipher API
 * - ECDSA verification on secp256r1 and secp521r1
 */
#ifndef OSNMA_MBEDTLS_CONFIG_H
#define OSNMA_MBEDTLS_CONFIG_H

/* Elliptic curves used by OSNMA public keys. */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM

/* Symmetric cryptography and MAC. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CMAC_C

/* Hashes and HMAC. */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA3_C

/* Multiprecision and elliptic-curve signature verification. */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C

/* P-521 values and intermediate calculations fit in 66 bytes. */
#define MBEDTLS_MPI_MAX_SIZE 72

/* Avoid the large fixed-point precomputation table: verification only. */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0

#endif /* OSNMA_MBEDTLS_CONFIG_H */
