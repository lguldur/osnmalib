#pragma once

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
    class BitWriter
    {
    public:
        void AppendBits(std::uint32_t value, int32_t bit_count);
        void AppendBytesMsb0(const std::uint8_t* data, int32_t bit_count);
        void AppendZeroBits(int32_t bit_count);
        void PadToByte();
        const std::vector<std::uint8_t>& Bytes() const;

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

    static void AppendRawWord(const GalileoNavWord& word,
        BitWriter& writer);

    static std::uint32_t GstSfTow32(const GnssTime& time);
};
