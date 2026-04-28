#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "osnma_types.h"

struct OsnmaDsmHeader
{
    int32_t dsm_id = -1;
    int32_t block_id = -1;
    int32_t total_blocks = -1;
};

struct OsnmaDsmBlock
{
    OsnmaDsmHeader header{};

    static constexpr int32_t MAX_PAYLOAD_BYTES = 13;
    std::array<std::uint8_t, MAX_PAYLOAD_BYTES> payload{};
};

class OsnmaDsmParser
{
public:
    bool ParseHKROOT(const std::array<std::uint8_t, 15>& hkroot,
                     OsnmaDsmBlock& out,
                     AuthReason& reason) const;
};
