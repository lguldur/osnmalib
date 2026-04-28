#include "osnma_mac_input.h"

#include "osnma_bit_utils.h"

void OsnmaMacInputBuilder::BitWriter::AppendBits(std::uint32_t value,
    int32_t bit_count)
{
    if (bit_count <= 0 || bit_count > 32)
        return;

    for (int32_t i = bit_count - 1; i >= 0; --i)
    {
        const bool bit =
            ((value >> i) & 0x01u) != 0;

        const int32_t byte_index = bit_count_ / 8;
        const int32_t bit_in_byte = bit_count_ % 8;

        if (bit_in_byte == 0)
            bytes_.push_back(0);

        if (bit)
        {
            bytes_[byte_index] |=
                static_cast<std::uint8_t>(1u << (7 - bit_in_byte));
        }

        ++bit_count_;
    }
}

void OsnmaMacInputBuilder::BitWriter::AppendBytesMsb0(const std::uint8_t* data,
    int32_t bit_count)
{
    if (data == nullptr || bit_count <= 0)
        return;

    for (int32_t i = 0; i < bit_count; ++i)
    {
        AppendBits(GetBitMsb0(data, i) ? 1u : 0u, 1);
    }
}

void OsnmaMacInputBuilder::BitWriter::AppendZeroBits(int32_t bit_count)
{
    if (bit_count <= 0)
        return;

    for (int32_t i = 0; i < bit_count; ++i)
        AppendBits(0u, 1);
}

void OsnmaMacInputBuilder::BitWriter::PadToByte()
{
    const int32_t rem = bit_count_ % 8;

    if (rem == 0)
        return;

    AppendZeroBits(8 - rem);
}

const std::vector<std::uint8_t>& OsnmaMacInputBuilder::BitWriter::Bytes() const
{
    return bytes_;
}

bool OsnmaMacInputBuilder::BuildTagMessage(const OsnmaMackMessage& mack,
    const OsnmaMackTagInfo& tag,
    const GalileoNavCandidate& candidate,
    std::uint8_t nmas,
    std::vector<std::uint8_t>& out)
{
    out.clear();

    if (!mack.valid_layout || !tag.valid_info)
        return false;

    if (tag.prnd < 0 || tag.prnd > 255)
        return false;

    if (mack.prn < 0 || mack.prn > 255)
        return false;

    BitWriter writer{};

    /*
        m = PRND || PRNA || GST_SF || CTR || NMAS || navdata || P

        PRND   = 8 bits
        PRNA   = 8 bits
        GST_SF = 32 bits
        CTR    = 8 bits
        NMAS   = 2 bits
        P      = zero-padding to whole bytes
    */

    writer.AppendBits(static_cast<std::uint32_t>(tag.prnd), 8);
    writer.AppendBits(static_cast<std::uint32_t>(mack.prn), 8);
    writer.AppendBits(GstSfTow32(mack.subframe_epoch), 32);
    writer.AppendBits(static_cast<std::uint32_t>(tag.index), 8);
    writer.AppendBits(static_cast<std::uint32_t>(nmas & 0x03u), 2);

    const bool dummy_tag = (tag.cop == 0);

    if (!BuildNavData(candidate,
        tag.adkd,
        dummy_tag,
        writer))
    {
        return false;
    }

    writer.PadToByte();

    out = writer.Bytes();
    return !out.empty();
}

bool OsnmaMacInputBuilder::BuildNavData(const GalileoNavCandidate& candidate,
    OsnmaAdkd adkd,
    bool dummy_tag,
    BitWriter& writer)
{
    if (adkd == OsnmaAdkd::InavCed ||
        adkd == OsnmaAdkd::SlowMac)
    {
        return BuildNavData_ADKD0(candidate, dummy_tag, writer);
    }

    if (adkd == OsnmaAdkd::InavTiming)
        return BuildNavData_ADKD4(candidate, dummy_tag, writer);

    return false;
}

bool OsnmaMacInputBuilder::BuildNavData_ADKD0(const GalileoNavCandidate& candidate,
    bool dummy_tag,
    BitWriter& writer)
{
    if (!candidate.HasCedData())
        return false;

    /*
        PROVISIONAL NAVDATA:
        ADKD=0/12 uses selected bits from WT1..WT5.
        The exact extraction masks are not in the SIS ICD text; SIS ICD points
        to AD.2 for masks. Until those masks are added, we append full raw
        120-bit pages as a stable placeholder.
    */

    static constexpr int32_t RAW_WT_BITS = GAL_INAV_BITS;
    static constexpr int32_t PROVISIONAL_ADKD0_BITS = RAW_WT_BITS * 5;

    if (dummy_tag)
    {
        writer.AppendZeroBits(PROVISIONAL_ADKD0_BITS);
        return true;
    }

    for (int32_t wt = GAL_WT1; wt <= GAL_WT5; ++wt)
    {
        const GalileoNavWord& word = candidate.words[wt];

        if (!word.valid)
            return false;

        AppendRawWord(word, writer);
    }

    return true;
}

bool OsnmaMacInputBuilder::BuildNavData_ADKD4(const GalileoNavCandidate& candidate,
    bool dummy_tag,
    BitWriter& writer)
{
    if (!candidate.HasTimingData())
        return false;

    /*
        PROVISIONAL NAVDATA:
        ADKD=4 uses selected bits from WT6 and WT10.
        The exact extraction masks are not in the SIS ICD text; SIS ICD points
        to AD.2 for masks. Until those masks are added, we append full raw
        WT6 + WT10 120-bit pages as a stable placeholder.
    */

    static constexpr int32_t RAW_WT_BITS = GAL_INAV_BITS;
    static constexpr int32_t PROVISIONAL_ADKD4_BITS = RAW_WT_BITS * 2;

    if (dummy_tag)
    {
        writer.AppendZeroBits(PROVISIONAL_ADKD4_BITS);
        return true;
    }

    AppendRawWord(candidate.words[GAL_WT6], writer);
    AppendRawWord(candidate.words[GAL_WT10], writer);

    return true;
}

void OsnmaMacInputBuilder::AppendRawWord(const GalileoNavWord& word,
    BitWriter& writer)
{
    writer.AppendBytesMsb0(word.even.data(), GAL_INAV_BITS);
}

std::uint32_t OsnmaMacInputBuilder::GstSfTow32(const GnssTime& time)
{
    if (time.tow <= 0.0)
        return 0;

    return static_cast<std::uint32_t>(time.tow);
}
