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
        AppendBits(GetBitMsb0(data, i) ? 1u : 0u, 1);
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

const std::vector<std::uint8_t>&
OsnmaMacInputBuilder::BitWriter::Bytes() const
{
    return bytes_;
}

int32_t OsnmaMacInputBuilder::BitWriter::BitCount() const
{
    return bit_count_;
}

bool OsnmaMacInputBuilder::BuildTag0Message(const OsnmaMackMessage& mack,
    const GalileoNavCandidate& candidate,
    std::uint8_t nmas,
    std::vector<std::uint8_t>& out)
{
    out.clear();

    if (!mack.valid_layout)
        return false;

    if (mack.prn <= 0 || mack.prn > 255)
        return false;

    /*
        Tag0 is always self-authenticated ADKD=0 CED/status.

        PRND = PRNA = authenticating satellite
        CTR  = 1
        ADKD = 0
    */

    const std::uint8_t prna =
        static_cast<std::uint8_t>(mack.prn);

    return BuildCommonMessage(prna,
        prna,
        GstSf32(mack.subframe_epoch),
        1,
        nmas,
        OsnmaAdkd::InavCed,
        false,
        candidate,
        out);
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

    if (tag.prnd <= 0 || tag.prnd > 255)
        return false;

    if (mack.prn <= 0 || mack.prn > 255)
        return false;

    if (tag.index < 0)
        return false;

    /*
        For Tag-Info entries:
            CTR = tag index + 1

        This matches Tag0 CTR=1 and Tag-Info entries following it.
    */

    const std::uint8_t prnd =
        static_cast<std::uint8_t>(tag.prnd);

    const std::uint8_t prna =
        static_cast<std::uint8_t>(mack.prn);

    const std::uint8_t ctr =
        static_cast<std::uint8_t>(tag.index + 1);

    const bool dummy_tag =
        (tag.cop == 0);

    return BuildCommonMessage(prnd,
        prna,
        GstSf32(mack.subframe_epoch),
        ctr,
        nmas,
        tag.adkd,
        dummy_tag,
        candidate,
        out);
}

bool OsnmaMacInputBuilder::BuildCommonMessage(std::uint8_t prnd,
    std::uint8_t prna,
    std::uint32_t gst_sf,
    std::uint8_t ctr,
    std::uint8_t nmas,
    OsnmaAdkd adkd,
    bool dummy_tag,
    const GalileoNavCandidate& candidate,
    std::vector<std::uint8_t>& out)
{
    out.clear();

    if (prnd == 0 || prna == 0)
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

    writer.AppendBits(static_cast<std::uint32_t>(prnd), 8);
    writer.AppendBits(static_cast<std::uint32_t>(prna), 8);
    writer.AppendBits(gst_sf, 32);
    writer.AppendBits(static_cast<std::uint32_t>(ctr), 8);
    writer.AppendBits(static_cast<std::uint32_t>(nmas & 0x03u), 2);

    if (!BuildNavData(candidate,
        adkd,
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
        ADKD=0 / ADKD=12 authenticated CED + status data.

        Extracted ranges, MSB0 bit indexing:
            WT1  [6, 126)  -> 120 bits
            WT2  [6, 126)  -> 120 bits
            WT3  [6, 128)  -> 122 bits
            WT4  [6, 126)  -> 120 bits
            WT5  [6, 73)   -> 67 bits

        Total: 549 bits.
    */

    static constexpr std::array<NavDataRange, 5> ranges =
    {
        NavDataRange{GAL_WT1, 6, 120},
        NavDataRange{GAL_WT2, 6, 120},
        NavDataRange{GAL_WT3, 6, 122},
        NavDataRange{GAL_WT4, 6, 120},
        NavDataRange{GAL_WT5, 6, 67}
    };

    return AppendRanges(candidate,
        ranges.data(),
        static_cast<int32_t>(ranges.size()),
        dummy_tag,
        writer);
}

bool OsnmaMacInputBuilder::BuildNavData_ADKD4(const GalileoNavCandidate& candidate,
    bool dummy_tag,
    BitWriter& writer)
{
    if (!candidate.HasTimingData())
        return false;

    /*
        ADKD=4 authenticated timing parameters.

        Extracted ranges, MSB0 bit indexing:
            WT6   [6, 105)   -> 99 bits
            WT10  [86, 128)  -> 42 bits

        Total: 141 bits.
    */

    static constexpr std::array<NavDataRange, 2> ranges =
    {
        NavDataRange{GAL_WT6, 6, 99},
        NavDataRange{GAL_WT10, 86, 42}
    };

    return AppendRanges(candidate,
        ranges.data(),
        static_cast<int32_t>(ranges.size()),
        dummy_tag,
        writer);
}

bool OsnmaMacInputBuilder::AppendRanges(const GalileoNavCandidate& candidate,
    const NavDataRange* ranges,
    int32_t range_count,
    bool dummy_tag,
    BitWriter& writer)
{
    if (ranges == nullptr || range_count <= 0)
        return false;

    for (int32_t i = 0; i < range_count; ++i)
    {
        if (!AppendRange(candidate,
            ranges[i],
            dummy_tag,
            writer))
        {
            return false;
        }
    }

    return true;
}

bool OsnmaMacInputBuilder::AppendRange(const GalileoNavCandidate& candidate,
    const NavDataRange& range,
    bool dummy_tag,
    BitWriter& writer)
{
    if (range.wt < 0 || range.wt > GAL_MAX_WT)
        return false;

    if (range.first_bit < 0 || range.bit_count <= 0)
        return false;

    if ((range.first_bit + range.bit_count) > GAL_INAV_BITS)
        return false;

    if (!candidate.HasWord(range.wt))
        return false;

    const GalileoNavWord& word =
        candidate.words[range.wt];

    if (!word.valid)
        return false;

    if (dummy_tag)
    {
        writer.AppendZeroBits(range.bit_count);
        return true;
    }

    for (int32_t i = 0; i < range.bit_count; ++i)
    {
        const bool bit =
            GetBitMsb0(word.even.data(), range.first_bit + i);

        writer.AppendBits(bit ? 1u : 0u, 1);
    }

    return true;
}

std::uint32_t OsnmaMacInputBuilder::GstSf32(const GnssTime& time)
{
    if (!IsTimeValid(time))
        return 0;

    /*
        Same GST_SF convention as MACSEQ:
        Galileo E1 I/NAV sub-frame start time minus 1 second.
    */

    int32_t wn = time.wn;
    double tow_d = time.tow - 1.0;

    while (tow_d < 0.0)
    {
        --wn;
        tow_d += 604800.0;
    }

    while (tow_d >= 604800.0)
    {
        ++wn;
        tow_d -= 604800.0;
    }

    const std::uint32_t wn_u =
        static_cast<std::uint32_t>(wn) & 0x0FFFu;

    const std::uint32_t tow_u =
        static_cast<std::uint32_t>(tow_d) & 0x000FFFFFu;

    return (wn_u << 20) | tow_u;
}
