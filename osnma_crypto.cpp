// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include "osnma_crypto.h"

#include <array>
#include <cstdio>
#include <cstddef>
#include <cstdint>

#include "mbedtls/cmac.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha3.h"

#ifndef OSNMA_VERBOSE_CRYPTO
#define OSNMA_VERBOSE_CRYPTO 0
#endif

namespace
{
    bool IsValidBuffer(const std::uint8_t* p, int32_t n)
    {
        return (p != nullptr) && (n >= 0);
    }

    bool ComputeSha256(const std::uint8_t* data,
        int32_t size_bytes,
        std::array<unsigned char, 32>& hash)
    {
        if (!IsValidBuffer(data, size_bytes))
            return false;

        const int rc =
            mbedtls_sha256(reinterpret_cast<const unsigned char*>(data),
                static_cast<size_t>(size_bytes),
                hash.data(),
                0);

        return rc == 0;
    }

    bool ComputeSha3_256(const std::uint8_t* data,
        int32_t size_bytes,
        std::array<unsigned char, 32>& hash)
    {
        if (!IsValidBuffer(data, size_bytes))
            return false;

        const int rc =
            mbedtls_sha3(MBEDTLS_SHA3_256,
                reinterpret_cast<const unsigned char*>(data),
                static_cast<size_t>(size_bytes),
                hash.data(),
                hash.size());

        return rc == 0;
    }

    bool ComputeSha512(const std::uint8_t* data,
        int32_t size_bytes,
        std::array<unsigned char, 64>& hash)
    {
        if (!IsValidBuffer(data, size_bytes))
            return false;

        const int rc =
            mbedtls_sha512(reinterpret_cast<const unsigned char*>(data),
                static_cast<size_t>(size_bytes),
                hash.data(),
                0);

        return rc == 0;
    }

    bool EcdsaVerifyRawSignature(mbedtls_ecp_group_id group_id,
        const std::uint8_t* public_key,
        int32_t public_key_size_bytes,
        const unsigned char* hash,
        int32_t hash_size_bytes,
        const std::uint8_t* signature,
        int32_t signature_size_bytes)
    {
#if OSNMA_VERBOSE_CRYPTO
        printf("ECDSA raw verify input: group_id=%d pk_size=%d pk_first=%02X "
            "hash_size=%d sig_size=%d\n",
            static_cast<int32_t>(group_id),
            public_key_size_bytes,
            public_key_size_bytes > 0 && public_key != nullptr ? public_key[0] : 0,
            hash_size_bytes,
            signature_size_bytes);
#endif

        if (!IsValidBuffer(public_key, public_key_size_bytes) ||
            !IsValidBuffer(signature, signature_size_bytes) ||
            hash == nullptr ||
            hash_size_bytes <= 0)
        {
            printf("ECDSA raw verify failed: invalid input buffer\n");
            return false;
        }

        if ((signature_size_bytes % 2) != 0)
        {
            printf("ECDSA raw verify failed: odd signature size\n");
            return false;
        }

        const int32_t scalar_size = signature_size_bytes / 2;

        mbedtls_ecp_group grp;
        mbedtls_ecp_point q;
        mbedtls_mpi r;
        mbedtls_mpi s;

        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&q);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        bool ok = false;

        do
        {
            int rc = mbedtls_ecp_group_load(&grp, group_id);

            if (rc != 0)
            {
                printf("ECDSA raw verify failed: mbedtls_ecp_group_load rc=%d\n", rc);
                break;
            }

            /*
                Expected public key format:
                    SEC1 encoded point accepted by Mbed TLS.

                Usually:
                    P-256 uncompressed: 65 bytes, 0x04 || X || Y
                    P-521 uncompressed: 133 bytes, 0x04 || X || Y

                OSNMA/GSC currently gives P-256 compressed keys:
                    33 bytes, 0x02/0x03 || X

                If this printf shows pk_size=33 pk_first=02 or 03,
                and mbedtls_ecp_point_read_binary fails, then we need
                compressed-point decompression.
            */
            rc = mbedtls_ecp_point_read_binary(
                &grp,
                &q,
                reinterpret_cast<const unsigned char*>(public_key),
                static_cast<size_t>(public_key_size_bytes));

            if (rc != 0)
            {
                printf("ECDSA raw verify failed: mbedtls_ecp_point_read_binary rc=%d "
                    "pk_size=%d pk_first=%02X\n",
                    rc,
                    public_key_size_bytes,
                    public_key_size_bytes > 0 ? public_key[0] : 0);
                break;
            }

            rc = mbedtls_mpi_read_binary(
                &r,
                reinterpret_cast<const unsigned char*>(signature),
                static_cast<size_t>(scalar_size));

            if (rc != 0)
            {
                printf("ECDSA raw verify failed: mbedtls_mpi_read_binary r rc=%d\n", rc);
                break;
            }

            rc = mbedtls_mpi_read_binary(
                &s,
                reinterpret_cast<const unsigned char*>(signature + scalar_size),
                static_cast<size_t>(scalar_size));

            if (rc != 0)
            {
                printf("ECDSA raw verify failed: mbedtls_mpi_read_binary s rc=%d\n", rc);
                break;
            }

            rc = mbedtls_ecdsa_verify(&grp,
                hash,
                static_cast<size_t>(hash_size_bytes),
                &q,
                &r,
                &s);

            if (rc != 0)
            {
                printf("ECDSA raw verify failed: mbedtls_ecdsa_verify rc=%d\n", rc);
                break;
            }

#if OSNMA_VERBOSE_CRYPTO
            printf("ECDSA raw verify OK\n");
#endif
            ok = true;
        } while (false);

        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_point_free(&q);
        mbedtls_ecp_group_free(&grp);

        return ok;
    }
}

bool OsnmaSha256(const std::uint8_t* data,
    int32_t size_bytes,
    std::uint8_t* out_32_bytes)
{
    if (!IsValidBuffer(data, size_bytes) || out_32_bytes == nullptr)
        return false;

    std::array<unsigned char, 32> hash{};

    if (!ComputeSha256(data, size_bytes, hash))
        return false;

    for (int32_t i = 0; i < 32; ++i)
        out_32_bytes[i] = static_cast<std::uint8_t>(hash[i]);

    return true;
}

bool OsnmaSha3_256(const std::uint8_t* data,
    int32_t size_bytes,
    std::uint8_t* out_32_bytes)
{
    if (!IsValidBuffer(data, size_bytes) || out_32_bytes == nullptr)
        return false;

    std::array<unsigned char, 32> hash{};

    if (!ComputeSha3_256(data, size_bytes, hash))
        return false;

    for (int32_t i = 0; i < 32; ++i)
        out_32_bytes[i] = static_cast<std::uint8_t>(hash[i]);

    return true;
}

bool OsnmaHmacSha256(const std::uint8_t* key,
    int32_t key_size_bytes,
    const std::uint8_t* data,
    int32_t data_size_bytes,
    std::uint8_t* out_mac,
    int32_t out_mac_size_bytes)
{
    if (!IsValidBuffer(key, key_size_bytes) ||
        !IsValidBuffer(data, data_size_bytes) ||
        out_mac == nullptr ||
        out_mac_size_bytes <= 0)
    {
        return false;
    }

    std::array<unsigned char, 32> full_mac{};

    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (info == nullptr)
        return false;

    const int rc =
        mbedtls_md_hmac(info,
            reinterpret_cast<const unsigned char*>(key),
            static_cast<size_t>(key_size_bytes),
            reinterpret_cast<const unsigned char*>(data),
            static_cast<size_t>(data_size_bytes),
            full_mac.data());

    if (rc != 0)
        return false;

    const int32_t copy_size =
        (out_mac_size_bytes < 32) ? out_mac_size_bytes : 32;

    for (int32_t i = 0; i < copy_size; ++i)
        out_mac[i] = static_cast<std::uint8_t>(full_mac[i]);

    return true;
}

bool OsnmaAesCmac(const std::uint8_t* key,
    int32_t key_size_bytes,
    const std::uint8_t* data,
    int32_t data_size_bytes,
    std::uint8_t* out_mac_16_bytes)
{
    if (!IsValidBuffer(key, key_size_bytes) ||
        !IsValidBuffer(data, data_size_bytes) ||
        out_mac_16_bytes == nullptr)
    {
        return false;
    }

    if (key_size_bytes != 16 && key_size_bytes != 24 && key_size_bytes != 32)
        return false;

    const mbedtls_cipher_type_t cipher_type =
        (key_size_bytes == 16) ? MBEDTLS_CIPHER_AES_128_ECB :
        (key_size_bytes == 24) ? MBEDTLS_CIPHER_AES_192_ECB :
        MBEDTLS_CIPHER_AES_256_ECB;

    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(cipher_type);

    if (cipher_info == nullptr)
        return false;

    unsigned char mac[16] = {};

    const int rc =
        mbedtls_cipher_cmac(cipher_info,
            reinterpret_cast<const unsigned char*>(key),
            static_cast<size_t>(key_size_bytes * 8),
            reinterpret_cast<const unsigned char*>(data),
            static_cast<size_t>(data_size_bytes),
            mac);

    if (rc != 0)
        return false;

    for (int32_t i = 0; i < 16; ++i)
        out_mac_16_bytes[i] = static_cast<std::uint8_t>(mac[i]);

    return true;
}

bool OsnmaEcdsaVerifyP256Sha256(const std::uint8_t* public_key,
    int32_t public_key_size_bytes,
    const std::uint8_t* message,
    int32_t message_size_bytes,
    const std::uint8_t* signature,
    int32_t signature_size_bytes)
{
    if (!IsValidBuffer(message, message_size_bytes))
        return false;

    std::array<unsigned char, 32> hash{};

    if (!ComputeSha256(message, message_size_bytes, hash))
        return false;

    return EcdsaVerifyRawSignature(MBEDTLS_ECP_DP_SECP256R1,
        public_key,
        public_key_size_bytes,
        hash.data(),
        static_cast<int32_t>(hash.size()),
        signature,
        signature_size_bytes);
}

bool OsnmaEcdsaVerifyP521Sha512(const std::uint8_t* public_key,
    int32_t public_key_size_bytes,
    const std::uint8_t* message,
    int32_t message_size_bytes,
    const std::uint8_t* signature,
    int32_t signature_size_bytes)
{
    if (!IsValidBuffer(message, message_size_bytes))
        return false;

    std::array<unsigned char, 64> hash{};

    if (!ComputeSha512(message, message_size_bytes, hash))
        return false;

    return EcdsaVerifyRawSignature(MBEDTLS_ECP_DP_SECP521R1,
        public_key,
        public_key_size_bytes,
        hash.data(),
        static_cast<int32_t>(hash.size()),
        signature,
        signature_size_bytes);
}
