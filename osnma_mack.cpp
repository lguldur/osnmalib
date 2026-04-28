#include "osnma_mack.h"

#include "osnma_bit_utils.h"

int32_t OsnmaMackProcessor::BytesForBits(int32_t bits)
{
    if (bits <= 0)
        return 0;

    return (bits + 7) / 8;
}

OsnmaAdkd OsnmaMackProcessor::AdkdFromValue(int32_t value)
{
    switch (value)
    {
    case 0:
        return OsnmaAdkd::InavCed;

    case 4:
        return OsnmaAdkd::InavTiming;

    case 12:
        return OsnmaAdkd::SlowMac;

    default:
        return OsnmaAdkd::Reserved;
    }
}

bool OsnmaMackProcessor::ParseMack(const OsnmaSubframe& subframe,
    int32_t key_size_bits,
    int32_t tag_size_bits,
    OsnmaMackMessage& out,
    AuthReason& reason_out) const
{
    out = OsnmaMackMessage{};

    if (subframe.prn <= 0)
    {
        reason_out = AuthReason::InvalidPrn;
        return false;
    }

    if (key_size_bits <= 0 ||
        key_size_bits > OsnmaMackMessage::MAX_KEY_BYTES * 8 ||
        (key_size_bits % 8) != 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (tag_size_bits <= 0 ||
        tag_size_bits > OsnmaMackTagInfo::MAX_TAG_BYTES * 8)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t tag_and_info_bits = tag_size_bits + 16;

    if (tag_and_info_bits <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t usable_bits =
        OsnmaMackMessage::MACK_BITS - key_size_bits;

    if (usable_bits <= 0 || (usable_bits % tag_and_info_bits) != 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t total_tag_count =
        usable_bits / tag_and_info_bits;

    if (total_tag_count <= 0 ||
        total_tag_count > OsnmaMackMessage::MAX_TAGS)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    out.prn = subframe.prn;
    out.subframe_epoch = subframe.subframe_epoch;

    out.key_size_bits = key_size_bits;
    out.key_size_bytes = key_size_bits / 8;

    out.tag_size_bits = tag_size_bits;
    out.tag_size_bytes = BytesForBits(tag_size_bits);

    out.total_tag_count = total_tag_count;
    out.tag_info_count = total_tag_count - 1;

    for (int32_t i = 0; i < OsnmaMackMessage::MACK_BYTES; ++i)
    {
        out.raw[i] = subframe.mack[i];
    }

    const std::uint8_t* data = out.raw.data();

    CopyBitsMsb0(data,
        0,
        tag_size_bits,
        out.tag0.data(),
        static_cast<int32_t>(out.tag0.size()));

    out.macseq =
        GetUnsignedBitsMsb0(data,
            tag_size_bits,
            12);

    out.cop =
        GetUnsignedBitsMsb0(data,
            tag_size_bits + 12,
            4);

    for (int32_t n = 1; n < total_tag_count; ++n)
    {
        const int32_t section_start =
            n * tag_and_info_bits;

        OsnmaMackTagInfo info{};

        info.index = n;
        info.tag_size_bits = tag_size_bits;
        info.tag_size_bytes = BytesForBits(tag_size_bits);

        CopyBitsMsb0(data,
            section_start,
            tag_size_bits,
            info.tag.data(),
            static_cast<int32_t>(info.tag.size()));

        const int32_t info_start =
            section_start + tag_size_bits;

        info.prnd =
            GetUnsignedBitsMsb0(data,
                info_start,
                8);

        const int32_t adkd_value =
            GetUnsignedBitsMsb0(data,
                info_start + 8,
                4);

        info.adkd = AdkdFromValue(adkd_value);

        info.cop =
            GetUnsignedBitsMsb0(data,
                info_start + 12,
                4);

        info.valid_info =
            (info.prnd >= 1 && info.prnd <= 255) &&
            (info.adkd != OsnmaAdkd::Reserved);

        out.tag_info[n - 1] = info;
    }

    const int32_t key_start =
        tag_and_info_bits * total_tag_count;

    if ((key_start + key_size_bits) > OsnmaMackMessage::MACK_BITS)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    CopyBitsMsb0(data,
        key_start,
        key_size_bits,
        out.disclosed_key.data(),
        static_cast<int32_t>(out.disclosed_key.size()));

    out.valid_layout = true;
    reason_out = AuthReason::None;
    return true;
}
