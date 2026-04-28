#pragma once

#include <cstddef>
#include <cstdint>

bool OsnmaSha256(const std::uint8_t* data,
                 int32_t size_bytes,
                 std::uint8_t* out_32_bytes);

bool OsnmaSha512(const std::uint8_t* data,
                 int32_t size_bytes,
                 std::uint8_t* out_64_bytes);

bool OsnmaHmacSha256(const std::uint8_t* key,
                     int32_t key_size_bytes,
                     const std::uint8_t* data,
                     int32_t data_size_bytes,
                     std::uint8_t* out_mac,
                     int32_t out_mac_size_bytes);

bool OsnmaAesCmac(const std::uint8_t* key,
                  int32_t key_size_bytes,
                  const std::uint8_t* data,
                  int32_t data_size_bytes,
                  std::uint8_t* out_mac_16_bytes);

bool OsnmaEcdsaVerifyP256Sha256(const std::uint8_t* public_key,
                                int32_t public_key_size_bytes,
                                const std::uint8_t* message,
                                int32_t message_size_bytes,
                                const std::uint8_t* signature,
                                int32_t signature_size_bytes);

bool OsnmaEcdsaVerifyP521Sha512(const std::uint8_t* public_key,
                                int32_t public_key_size_bytes,
                                const std::uint8_t* message,
                                int32_t message_size_bytes,
                                const std::uint8_t* signature,
                                int32_t signature_size_bytes);
								