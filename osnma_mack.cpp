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

    const int32_t mack_header_bits =
        tag_size_bits + 12 + 4;   // Tag0 || MACSEQ || COP

    const int32_t tag_and_info_bits =
        tag_size_bits + 16;       // Tag || PRND || ADKD || COP

    if (mack_header_bits <= 0 ||
        tag_and_info_bits <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    /*
        MACK layout:

            Tag0 || MACSEQ || COP ||
            repeated(Tag || Tag-Info) ||
            disclosed TESLA key ||
            zero padding

        Do NOT require exact divisibility up to 480 bits.
        The remainder after the disclosed key is padding.
    */

    const int32_t available_for_tag_info_bits =
        OsnmaMackMessage::MACK_BITS -
        mack_header_bits -
        key_size_bits;

    if (available_for_tag_info_bits < 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t tag_info_count =
        available_for_tag_info_bits / tag_and_info_bits;

    const int32_t padding_bits =
        available_for_tag_info_bits -
        tag_info_count * tag_and_info_bits;

    if (tag_info_count < 0 ||
        tag_info_count > OsnmaMackMessage::MAX_TAGS - 1)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (padding_bits < 0 ||
        padding_bits >= tag_and_info_bits)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t total_tag_count =
        1 + tag_info_count;       // Tag0 + flexible tags

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
    out.tag_info_count = tag_info_count;

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

    const int32_t tag_info_base =
        mack_header_bits;

    for (int32_t n = 0; n < tag_info_count; ++n)
    {
        const int32_t section_start =
            tag_info_base + n * tag_and_info_bits;

        OsnmaMackTagInfo info{};

        /*
            Keep indexes compatible with your existing CTR logic:
            Tag0 has implicit index 0.
            First Tag+Info entry is index 1.
        */
        info.index = n + 1;
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

        out.tag_info[n] = info;
    }

    const int32_t key_start =
        mack_header_bits + tag_info_count * tag_and_info_bits;

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

    /*
        Optional debug:
        For KS=128, TS=40, we expect:
            mack_header_bits = 56
            tag_info_count   = 5
            key_start        = 336
            padding_bits     = 16
    */
    /*
    printf("MACK parse geometry: KS=%d TS=%d header=%d tag_info_count=%d key_start=%d padding=%d MACSEQ=%d COP=%d\n",
           key_size_bits,
           tag_size_bits,
           mack_header_bits,
           tag_info_count,
           key_start,
           padding_bits,
           out.macseq,
           out.cop);
    */

    out.valid_layout = true;
    reason_out = AuthReason::None;
    return true;
}
