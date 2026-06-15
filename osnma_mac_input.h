#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "galileo_nav_candidate.h"
#include "osnma_mack.h"

class OsnmaMacInputBuilder
{
public:
    static bool BuildTagMessage(const OsnmaMackMessage& mack,
        const OsnmaMackTagInfo& tag,
        const GalileoNavCandidate& candidate,
        std::uint8_t nmas,
        std::vector<std::uint8_t>& out);

private:
    struct NavDataRange
    {
        int32_t wt = 0;
        int32_t first_bit = 0;
        int32_t bit_count = 0;
    };

    class BitWriter
    {
    public:
        void AppendBits(std::uint32_t value, int32_t bit_count);
        void AppendBytesMsb0(const std::uint8_t* data, int32_t bit_count);
        void AppendZeroBits(int32_t bit_count);
        void PadToByte();

        const std::vector<std::uint8_t>& Bytes() const;
        int32_t BitCount() const;

    private:
        std::vector<std::uint8_t> bytes_{};
        int32_t bit_count_ = 0;
    };

private:
    static bool BuildNavData(const GalileoNavCandidate& candidate,
        OsnmaAdkd adkd,
        bool dummy_tag,
        BitWriter& writer);

    static bool BuildNavData_ADKD0(const GalileoNavCandidate& candidate,
        bool dummy_tag,
        BitWriter& writer);

    static bool BuildNavData_ADKD4(const GalileoNavCandidate& candidate,
        bool dummy_tag,
        BitWriter& writer);

    static bool AppendRanges(const GalileoNavCandidate& candidate,
        const NavDataRange* ranges,
        int32_t range_count,
        bool dummy_tag,
        BitWriter& writer);

    static bool AppendRange(const GalileoNavCandidate& candidate,
        const NavDataRange& range,
        bool dummy_tag,
        BitWriter& writer);

    static std::uint32_t GstSf32(const GnssTime& time);
};
