#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "osnma_dsm.h"
#include "osnma_types.h"

enum class OsnmaHashFunction : int32_t
{
    Sha256 = 0,
    Sha3_256 = 2,
    Reserved = -1
};

enum class OsnmaMacFunction : int32_t
{
    HmacSha256 = 0,
    CmacAes = 1,
    Reserved = -1
};

enum class OsnmaEcdsaFunction : int32_t
{
    Unknown = 0,
    P256Sha256,
    P521Sha512
};

enum class OsnmaNewPublicKeyType : int32_t
{
    Unknown = 0,
    EcdsaP256Sha256 = 1,
    EcdsaP521Sha512 = 3,
    OsnmaAlertMessage = 4,
    Reserved = -1
};

struct OsnmaDsmKroot
{
    std::uint8_t nma_header = 0;

    int32_t number_of_blocks = -1;
    int32_t public_key_id = -1;
    int32_t kroot_chain_id = -1;

    OsnmaHashFunction hash_function = OsnmaHashFunction::Reserved;
    OsnmaMacFunction mac_function = OsnmaMacFunction::Reserved;

    int32_t key_size_bits = -1;
    int32_t tag_size_bits = -1;
    int32_t mac_lookup_table = -1;

    int32_t kroot_wn = -1;
    int32_t kroot_towh = -1;

    uint64_t alpha = 0;

    static constexpr int32_t MAX_RAW_BYTES = 256;
    static constexpr int32_t MAX_KROOT_BYTES = 32;
    static constexpr int32_t MAX_SIGNATURE_BYTES = 132;
    static constexpr int32_t MAX_PADDING_BYTES = 32;

    int32_t raw_size_bytes = 0;
    std::array<std::uint8_t, MAX_RAW_BYTES> raw{};

    int32_t kroot_size_bytes = 0;
    std::array<std::uint8_t, MAX_KROOT_BYTES> kroot{};

    OsnmaEcdsaFunction ecdsa_function = OsnmaEcdsaFunction::Unknown;

    int32_t signature_offset_bytes = 0;
    int32_t signature_size_bytes = 0;
    std::array<std::uint8_t, MAX_SIGNATURE_BYTES> signature{};

    int32_t padding_size_bytes = 0;
    std::array<std::uint8_t, MAX_PADDING_BYTES> padding{};

    bool valid_layout = false;
};

struct OsnmaDsmPkr
{
    int32_t number_of_blocks = -1;
    int32_t message_id = -1;

    static constexpr int32_t MERKLE_NODE_BYTES = 32;
    static constexpr int32_t MERKLE_NODE_COUNT = 4;

    std::array<std::array<std::uint8_t, MERKLE_NODE_BYTES>, MERKLE_NODE_COUNT> intermediate_tree_nodes{};

    OsnmaNewPublicKeyType new_public_key_type = OsnmaNewPublicKeyType::Unknown;
    int32_t new_public_key_id = -1;

    static constexpr int32_t MAX_PUBLIC_KEY_BYTES = 80;
    static constexpr int32_t MAX_PADDING_BYTES = 80;

    int32_t public_key_size_bytes = 0;
    std::array<std::uint8_t, MAX_PUBLIC_KEY_BYTES> public_key{};

    int32_t padding_size_bytes = 0;
    std::array<std::uint8_t, MAX_PADDING_BYTES> padding{};

    bool valid_layout = false;
};

struct OsnmaDecodedDsm
{
    OsnmaDsmType type = OsnmaDsmType::Unknown;

    OsnmaDsmKroot kroot{};
    OsnmaDsmPkr pkr{};
};

class OsnmaDsmContentDecoder
{
public:
    bool Decode(const OsnmaDsmMessage& message,
                OsnmaDecodedDsm& decoded,
                AuthReason& reason_out) const;

private:
    bool DecodeKroot(const OsnmaDsmMessage& message,
                     OsnmaDecodedDsm& decoded,
                     AuthReason& reason_out) const;

    bool DecodePkr(const OsnmaDsmMessage& message,
                   OsnmaDecodedDsm& decoded,
                   AuthReason& reason_out) const;

private:
    static uint32_t ReadBits(const std::uint8_t* data,
                             int32_t first_bit,
                             int32_t bit_count);

    static void CopyBytes(const std::uint8_t* src,
                          int32_t src_size,
                          int32_t src_offset,
                          std::uint8_t* dst,
                          int32_t dst_capacity,
                          int32_t count);

    static int32_t KrootNumberOfBlocksFromNb(int32_t nb);
    static int32_t PkrNumberOfBlocksFromNb(int32_t nb);

    static int32_t KrootKeySizeBitsFromKs(int32_t ks);
    static int32_t KrootTagSizeBitsFromTs(int32_t ts);

    static OsnmaHashFunction HashFunctionFromValue(int32_t value);
    static OsnmaMacFunction MacFunctionFromValue(int32_t value);
    static OsnmaNewPublicKeyType NewPublicKeyTypeFromValue(int32_t value);

    static int32_t PublicKeySizeBytes(OsnmaNewPublicKeyType type);
};
