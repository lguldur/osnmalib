#include "osnma_dsm_content.h"
#include "osnma_bit_utils.h"

#include <algorithm>

uint32_t OsnmaDsmContentDecoder::ReadBits(const std::uint8_t* data,
                                          int32_t first_bit,
                                          int32_t bit_count)
{
    uint32_t value = 0;

    for (int32_t i = 0; i < bit_count; ++i)
    {
        value <<= 1;
        value |= GetBitMsb0(data, first_bit + i) ? 1u : 0u;
    }

    return value;
}

void OsnmaDsmContentDecoder::CopyBytes(const std::uint8_t* src,
                                       int32_t src_size,
                                       int32_t src_offset,
                                       std::uint8_t* dst,
                                       int32_t dst_capacity,
                                       int32_t count)
{
    if (src_offset < 0 || count <= 0 || dst_capacity <= 0)
        return;

    if (src_offset >= src_size)
        return;

    const int32_t safe_count =
        std::min({count, dst_capacity, src_size - src_offset});

    for (int32_t i = 0; i < safe_count; ++i)
        dst[i] = src[src_offset + i];
}

int32_t OsnmaDsmContentDecoder::KrootNumberOfBlocksFromNb(int32_t nb)
{
    if (nb >= 1 && nb <= 8)
        return nb + 6;

    return -1;
}

int32_t OsnmaDsmContentDecoder::PkrNumberOfBlocksFromNb(int32_t nb)
{
    if (nb >= 7 && nb <= 10)
        return nb + 6;

    return -1;
}

int32_t OsnmaDsmContentDecoder::KrootKeySizeBitsFromKs(int32_t ks)
{
    switch (ks)
    {
    case 0: return 96;
    case 1: return 104;
    case 2: return 112;
    case 3: return 120;
    case 4: return 128;
    case 5: return 160;
    case 6: return 192;
    case 7: return 224;
    case 8: return 256;
    default: return -1;
    }
}

int32_t OsnmaDsmContentDecoder::KrootTagSizeBitsFromTs(int32_t ts)
{
    switch (ts)
    {
    case 5: return 20;
    case 6: return 24;
    case 7: return 28;
    case 8: return 32;
    case 9: return 40;
    default: return -1;
    }
}

OsnmaHashFunction OsnmaDsmContentDecoder::HashFunctionFromValue(int32_t value)
{
    switch (value)
    {
    case 0: return OsnmaHashFunction::Sha256;
    case 2: return OsnmaHashFunction::Sha3_256;
    default: return OsnmaHashFunction::Reserved;
    }
}

OsnmaMacFunction OsnmaDsmContentDecoder::MacFunctionFromValue(int32_t value)
{
    switch (value)
    {
    case 0: return OsnmaMacFunction::HmacSha256;
    case 1: return OsnmaMacFunction::CmacAes;
    default: return OsnmaMacFunction::Reserved;
    }
}

OsnmaNewPublicKeyType
OsnmaDsmContentDecoder::NewPublicKeyTypeFromValue(int32_t value)
{
    switch (value)
    {
    case 1: return OsnmaNewPublicKeyType::EcdsaP256Sha256;
    case 3: return OsnmaNewPublicKeyType::EcdsaP521Sha512;
    case 4: return OsnmaNewPublicKeyType::OsnmaAlertMessage;
    default: return OsnmaNewPublicKeyType::Reserved;
    }
}

int32_t OsnmaDsmContentDecoder::PublicKeySizeBytes(OsnmaNewPublicKeyType type)
{
    switch (type)
    {
    case OsnmaNewPublicKeyType::EcdsaP256Sha256:
        return 264 / 8;

    case OsnmaNewPublicKeyType::EcdsaP521Sha512:
        return 536 / 8;

    default:
        return -1;
    }
}

bool OsnmaDsmContentDecoder::Decode(const OsnmaDsmMessage& message,
                                    OsnmaDecodedDsm& decoded,
                                    AuthReason& reason_out) const
{
    decoded = OsnmaDecodedDsm{};
    decoded.type = message.type;

    if (message.byte_count <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (message.type == OsnmaDsmType::Kroot)
        return DecodeKroot(message, decoded, reason_out);

    if (message.type == OsnmaDsmType::Pkr)
        return DecodePkr(message, decoded, reason_out);

    reason_out = AuthReason::UnsupportedMessage;
    return false;
}

bool OsnmaDsmContentDecoder::DecodeKroot(const OsnmaDsmMessage& message,
                                         OsnmaDecodedDsm& decoded,
                                         AuthReason& reason_out) const
{
    const std::uint8_t* data = message.data.data();
    const int32_t size = message.byte_count;

    OsnmaDsmKroot out{};

    if (size > OsnmaDsmKroot::MAX_RAW_BYTES)
    {
        reason_out = AuthReason::BufferOverflow;
        return false;
    }

    out.raw_size_bytes = size;
    for (int32_t i = 0; i < size; ++i)
        out.raw[i] = data[i];

    const int32_t nb = static_cast<int32_t>(ReadBits(data, 0, 4));
    out.number_of_blocks = KrootNumberOfBlocksFromNb(nb);

    out.public_key_id = static_cast<int32_t>(ReadBits(data, 4, 4));
    out.kroot_chain_id = static_cast<int32_t>(ReadBits(data, 8, 2));

    out.hash_function =
        HashFunctionFromValue(static_cast<int32_t>(ReadBits(data, 12, 2)));

    out.mac_function =
        MacFunctionFromValue(static_cast<int32_t>(ReadBits(data, 14, 2)));

    const int32_t ks = static_cast<int32_t>(ReadBits(data, 16, 4));
    out.key_size_bits = KrootKeySizeBitsFromKs(ks);

    const int32_t ts = static_cast<int32_t>(ReadBits(data, 20, 4));
    out.tag_size_bits = KrootTagSizeBitsFromTs(ts);

    out.mac_lookup_table = static_cast<int32_t>(ReadBits(data, 24, 8));
    out.kroot_wn = static_cast<int32_t>(ReadBits(data, 36, 12));
    out.kroot_towh = static_cast<int32_t>(ReadBits(data, 48, 8));

    out.alpha = static_cast<uint64_t>(ReadBits(data, 56, 32));
    out.alpha <<= 16;
    out.alpha |= static_cast<uint64_t>(ReadBits(data, 88, 16));

    if (out.number_of_blocks <= 0 ||
        out.key_size_bits <= 0 ||
        out.tag_size_bits <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    out.kroot_size_bytes = out.key_size_bits / 8;

    if (out.kroot_size_bytes > OsnmaDsmKroot::MAX_KROOT_BYTES)
    {
        reason_out = AuthReason::BufferOverflow;
        return false;
    }

    static constexpr int32_t FIXED_KROOT_HEADER_BYTES = 13;

    CopyBytes(data,
              size,
              FIXED_KROOT_HEADER_BYTES,
              out.kroot.data(),
              OsnmaDsmKroot::MAX_KROOT_BYTES,
              out.kroot_size_bytes);

    const int32_t signature_offset =
        FIXED_KROOT_HEADER_BYTES + out.kroot_size_bytes;

    const int32_t remaining =
        size - signature_offset;

    if (remaining < 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t p256_signature_bytes = 64;
    const int32_t p521_signature_bytes = 132;

    if (remaining >= p256_signature_bytes)
    {
        const int32_t padding_if_p256 = remaining - p256_signature_bytes;

        if (padding_if_p256 >= 0 &&
            padding_if_p256 <= OsnmaDsmKroot::MAX_PADDING_BYTES)
        {
            out.ecdsa_function = OsnmaEcdsaFunction::P256Sha256;
            out.signature_offset_bytes = signature_offset;
            out.signature_size_bytes = p256_signature_bytes;

            CopyBytes(data,
                      size,
                      signature_offset,
                      out.signature.data(),
                      OsnmaDsmKroot::MAX_SIGNATURE_BYTES,
                      out.signature_size_bytes);

            out.padding_size_bytes = padding_if_p256;

            CopyBytes(data,
                      size,
                      signature_offset + out.signature_size_bytes,
                      out.padding.data(),
                      OsnmaDsmKroot::MAX_PADDING_BYTES,
                      out.padding_size_bytes);

            out.valid_layout = true;
            decoded.kroot = out;
            reason_out = AuthReason::None;
            return true;
        }
    }

    if (remaining >= p521_signature_bytes)
    {
        const int32_t padding_if_p521 = remaining - p521_signature_bytes;

        if (padding_if_p521 >= 0 &&
            padding_if_p521 <= OsnmaDsmKroot::MAX_PADDING_BYTES)
        {
            out.ecdsa_function = OsnmaEcdsaFunction::P521Sha512;
            out.signature_offset_bytes = signature_offset;
            out.signature_size_bytes = p521_signature_bytes;

            CopyBytes(data,
                      size,
                      signature_offset,
                      out.signature.data(),
                      OsnmaDsmKroot::MAX_SIGNATURE_BYTES,
                      out.signature_size_bytes);

            out.padding_size_bytes = padding_if_p521;

            CopyBytes(data,
                      size,
                      signature_offset + out.signature_size_bytes,
                      out.padding.data(),
                      OsnmaDsmKroot::MAX_PADDING_BYTES,
                      out.padding_size_bytes);

            out.valid_layout = true;
            decoded.kroot = out;
            reason_out = AuthReason::None;
            return true;
        }
    }

    reason_out = AuthReason::InvalidFrameFormat;
    return false;
}

bool OsnmaDsmContentDecoder::DecodePkr(const OsnmaDsmMessage& message,
                                       OsnmaDecodedDsm& decoded,
                                       AuthReason& reason_out) const
{
    const std::uint8_t* data = message.data.data();
    const int32_t size = message.byte_count;

    OsnmaDsmPkr out{};

    const int32_t nb = static_cast<int32_t>(ReadBits(data, 0, 4));
    out.number_of_blocks = PkrNumberOfBlocksFromNb(nb);
    out.message_id = static_cast<int32_t>(ReadBits(data, 4, 4));

    if (out.number_of_blocks <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    static constexpr int32_t FIRST_NODE_OFFSET_BYTES = 1;

    for (int32_t node = 0; node < OsnmaDsmPkr::MERKLE_NODE_COUNT; ++node)
    {
        CopyBytes(data,
                  size,
                  FIRST_NODE_OFFSET_BYTES + node * OsnmaDsmPkr::MERKLE_NODE_BYTES,
                  out.intermediate_tree_nodes[node].data(),
                  OsnmaDsmPkr::MERKLE_NODE_BYTES,
                  OsnmaDsmPkr::MERKLE_NODE_BYTES);
    }

    const int32_t npkt =
        static_cast<int32_t>(ReadBits(data, 1032, 4));

    out.new_public_key_type = NewPublicKeyTypeFromValue(npkt);
    out.new_public_key_id =
        static_cast<int32_t>(ReadBits(data, 1036, 4));

    out.public_key_size_bytes =
        PublicKeySizeBytes(out.new_public_key_type);

    static constexpr int32_t NEW_PUBLIC_KEY_OFFSET_BYTES = 1040 / 8;

    if (out.new_public_key_type == OsnmaNewPublicKeyType::OsnmaAlertMessage)
    {
        out.public_key_size_bytes = 0;
        out.padding_size_bytes = 0;
        out.valid_layout = true;
        decoded.pkr = out;
        reason_out = AuthReason::None;
        return true;
    }

    if (out.public_key_size_bytes <= 0 ||
        out.public_key_size_bytes > OsnmaDsmPkr::MAX_PUBLIC_KEY_BYTES)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    CopyBytes(data,
              size,
              NEW_PUBLIC_KEY_OFFSET_BYTES,
              out.public_key.data(),
              OsnmaDsmPkr::MAX_PUBLIC_KEY_BYTES,
              out.public_key_size_bytes);

    const int32_t used =
        NEW_PUBLIC_KEY_OFFSET_BYTES + out.public_key_size_bytes;

    if (used > size)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    out.padding_size_bytes = size - used;

    if (out.padding_size_bytes > OsnmaDsmPkr::MAX_PADDING_BYTES)
    {
        reason_out = AuthReason::BufferOverflow;
        return false;
    }

    CopyBytes(data,
              size,
              used,
              out.padding.data(),
              OsnmaDsmPkr::MAX_PADDING_BYTES,
              out.padding_size_bytes);

    out.valid_layout = true;
    decoded.pkr = out;
    reason_out = AuthReason::None;
    return true;
}
