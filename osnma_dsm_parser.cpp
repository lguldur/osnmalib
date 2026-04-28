#include "osnma_dsm_parser.h"
#include "osnma_bit_utils.h"

bool OsnmaDsmParser::ParseHKROOT(const std::array<std::uint8_t, 15>& hkroot,
                                 OsnmaDsmBlock& out,
                                 AuthReason& reason) const
{
    out = OsnmaDsmBlock{};

    const std::uint8_t* data = hkroot.data();

    // --- DSM header extraction ---
    // NOTE: bit positions based on OSNMA ICD (simplified first version)

    const int32_t dsm_id =
        GetBitMsb0(data, 0) << 3 |
        GetBitMsb0(data, 1) << 2 |
        GetBitMsb0(data, 2) << 1 |
        GetBitMsb0(data, 3);

    const int32_t block_id =
        GetBitMsb0(data, 4) << 3 |
        GetBitMsb0(data, 5) << 2 |
        GetBitMsb0(data, 6) << 1 |
        GetBitMsb0(data, 7);

    const int32_t total_blocks =
        GetBitMsb0(data, 8) << 3 |
        GetBitMsb0(data, 9) << 2 |
        GetBitMsb0(data,10) << 1 |
        GetBitMsb0(data,11);

    out.header.dsm_id = dsm_id;
    out.header.block_id = block_id;
    out.header.total_blocks = total_blocks;

    // --- Payload (remaining bits) ---
    CopyBitsMsb0(data,
                 12,
                 120 - 12,
                 out.payload.data(),
                 OsnmaDsmBlock::MAX_PAYLOAD_BYTES);

    reason = AuthReason::None;
    return true;
}
