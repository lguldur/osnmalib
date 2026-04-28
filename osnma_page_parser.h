#pragma once

#include <array>
#include "galileo_inav_page_parts.h"
#include "osnma_types.h"

struct ParsedPage
{
    GalileoInavPageParts page{};

    bool has_osnma = false;

    std::array<std::uint8_t, 5> osnma_field{};
    std::array<std::uint8_t, 1> hkroot_chunk{};
    std::array<std::uint8_t, 4> mack_chunk{};
};

class OsnmaPageParser
{
public:
    bool Parse(const GalileoInavPageParts& input,
               ParsedPage& parsed,
               AuthReason& reason_out) const;
};
