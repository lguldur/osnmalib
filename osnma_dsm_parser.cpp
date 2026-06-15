#include "osnma_dsm_parser.h"
#include "osnma_bit_utils.h"

bool OsnmaDsmParser::ParseHKROOT(const std::array<std::uint8_t, 15>& hkroot,
    OsnmaDsmBlock& out,
    AuthReason& reason) const
{
    out = OsnmaDsmBlock{};

    const std::uint8_t* data = hkroot.data();

    const int32_t dsm_id =
        GetUnsignedBitsMsb0(data, 0, 4);

    const int32_t block_id =
        GetUnsignedBitsMsb0(data, 4, 4);

    const int32_t total_blocks =
        GetUnsignedBitsMsb0(data, 8, 4);

    out.header.dsm_id = dsm_id;
    out.header.block_id = block_id;
    out.header.total_blocks = total_blocks;

    CopyBitsMsb0(data,
        12,
        120 - 12,
        out.payload.data(),
        OsnmaDsmBlock::MAX_PAYLOAD_BYTES);

    reason = AuthReason::None;
    return true;
}
