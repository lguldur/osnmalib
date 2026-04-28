#include "osnma_page_parser.h"
#include "osnma_bit_utils.h"

namespace
{
    static constexpr int32_t OSNMA_FIRST_BIT_IN_ODD = 19;
    static constexpr int32_t OSNMA_TOTAL_BITS = 40;
}

bool OsnmaPageParser::Parse(const GalileoInavPageParts& input,
                            ParsedPage& parsed,
                            AuthReason& reason_out) const
{
    parsed = ParsedPage{};
    parsed.page = input;

    if (input.prn <= 0)
    {
        reason_out = AuthReason::InvalidPrn;
        return false;
    }

    if (!input.crc_ok || input.odd == nullptr)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    CopyBitsMsb0(input.odd,
                 OSNMA_FIRST_BIT_IN_ODD,
                 OSNMA_TOTAL_BITS,
                 parsed.osnma_field.data(),
                 5);

    CopyBitsMsb0(parsed.osnma_field.data(), 0, 8,
                 parsed.hkroot_chunk.data(), 1);

    CopyBitsMsb0(parsed.osnma_field.data(), 8, 32,
                 parsed.mack_chunk.data(), 4);

    parsed.has_osnma = true;
    reason_out = AuthReason::None;
    return true;
}
