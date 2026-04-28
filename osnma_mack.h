#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "gnss_time.h"
#include "osnma_subframe_assembler.h"
#include "osnma_types.h"

enum class OsnmaAdkd : int32_t
{
    InavCed = 0,
    InavTiming = 4,
    SlowMac = 12,
    Reserved = -1
};

struct OsnmaMackTagInfo
{
    int32_t index = -1;

    int32_t tag_size_bits = 0;
    int32_t tag_size_bytes = 0;

    static constexpr int32_t MAX_TAG_BYTES = 8;
    std::array<std::uint8_t, MAX_TAG_BYTES> tag{};

    int32_t prnd = -1;
    OsnmaAdkd adkd = OsnmaAdkd::Reserved;
    int32_t cop = -1;

    bool valid_info = false;
};

struct OsnmaMackMessage
{
    int32_t prn = -1;
    GnssTime subframe_epoch{};

    static constexpr int32_t MACK_BYTES = 60;
    static constexpr int32_t MACK_BITS = 480;

    std::array<std::uint8_t, MACK_BYTES> raw{};

    int32_t key_size_bits = 0;
    int32_t key_size_bytes = 0;

    int32_t tag_size_bits = 0;
    int32_t tag_size_bytes = 0;

    static constexpr int32_t MAX_KEY_BYTES = 32;
    std::array<std::uint8_t, MAX_KEY_BYTES> disclosed_key{};

    static constexpr int32_t MAX_TAGS = 16;

    int32_t total_tag_count = 0;
    int32_t tag_info_count = 0;

    std::array<std::uint8_t, OsnmaMackTagInfo::MAX_TAG_BYTES> tag0{};

    int32_t macseq = -1;
    int32_t cop = -1;

    std::array<OsnmaMackTagInfo, MAX_TAGS> tag_info{};

    bool valid_layout = false;
};

class OsnmaMackProcessor
{
public:
    bool ParseMack(const OsnmaSubframe& subframe,
                   int32_t key_size_bits,
                   int32_t tag_size_bits,
                   OsnmaMackMessage& out,
                   AuthReason& reason_out) const;

private:
    static int32_t BytesForBits(int32_t bits);
    static OsnmaAdkd AdkdFromValue(int32_t value);
};
