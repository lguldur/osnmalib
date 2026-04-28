#include "osnma_dsm.h"

void OsnmaDsmAssembler::Reset()
{
    for (auto& s : sats_)
        s = SatState{};
}

bool OsnmaDsmAssembler::IsValidPrn(int32_t prn) const
{
    return prn > 0 && prn < MAX_PRN;
}

OsnmaDsmType OsnmaDsmAssembler::DsmTypeFromId(int32_t dsm_id)
{
    if (dsm_id >= 0 && dsm_id <= 11)
        return OsnmaDsmType::Kroot;

    if (dsm_id >= 12 && dsm_id <= 15)
        return OsnmaDsmType::Pkr;

    return OsnmaDsmType::Unknown;
}

OsnmaDsmHeader OsnmaDsmAssembler::ParseDsmHeader(uint8_t raw)
{
    OsnmaDsmHeader h{};
    h.raw = raw;
    h.dsm_id = static_cast<int32_t>((raw >> 4) & 0x0F);
    h.block_id = static_cast<int32_t>(raw & 0x0F);
    h.type = DsmTypeFromId(h.dsm_id);
    return h;
}

int32_t OsnmaDsmAssembler::NumberOfBlocks(OsnmaDsmType type, int32_t nb_value)
{
    if (type == OsnmaDsmType::Pkr)
    {
        switch (nb_value)
        {
        case 7:  return 13;
        case 8:  return 14;
        case 9:  return 15;
        case 10: return 16;
        default: return -1;
        }
    }

    if (type == OsnmaDsmType::Kroot)
    {
        switch (nb_value)
        {
        case 1: return 7;
        case 2: return 8;
        case 3: return 9;
        case 4: return 10;
        case 5: return 11;
        case 6: return 12;
        case 7: return 13;
        case 8: return 14;
        default: return -1;
        }
    }

    return -1;
}

bool OsnmaDsmAssembler::FeedBlock(const OsnmaDsmBlock& block,
                                  OsnmaDsmMessage& message_out)
{
    message_out = OsnmaDsmMessage{};

    if (!IsValidPrn(block.prn))
        return false;

    const OsnmaDsmHeader& header = block.dsm_header;

    if (header.type == OsnmaDsmType::Unknown)
        return false;

    if (header.block_id < 0 || header.block_id >= MAX_BLOCKS)
        return false;

    SatState& sat = sats_[static_cast<std::size_t>(block.prn)];

    if (!sat.active ||
        sat.done ||
        sat.dsm_id != header.dsm_id ||
        sat.type != header.type)
    {
        sat = SatState{};
        sat.active = true;
        sat.done = false;
        sat.dsm_id = header.dsm_id;
        sat.type = header.type;
    }

    sat.blocks[header.block_id] = block;
    sat.received[header.block_id] = true;

    return BuildIfComplete(sat, block, message_out);
}

bool OsnmaDsmAssembler::BuildIfComplete(SatState& sat,
                                        const OsnmaDsmBlock& latest_block,
                                        OsnmaDsmMessage& message_out)
{
    message_out = OsnmaDsmMessage{};

    // The number-of-blocks field is inside DSM data block 0.
    // Therefore we cannot know the DSM length until block 0 has arrived.
    if (!sat.received[0])
        return false;

    const uint8_t first_byte =
        static_cast<uint8_t>(sat.blocks[0].data[0]);

    const int32_t nb_value = static_cast<int32_t>((first_byte >> 4) & 0x0F);
    const int32_t expected_blocks = NumberOfBlocks(sat.type, nb_value);

    if (expected_blocks <= 0 || expected_blocks > MAX_BLOCKS)
        return false;

    for (int32_t i = 0; i < expected_blocks; ++i)
    {
        if (!sat.received[i])
            return false;
    }

    message_out.prn = latest_block.prn;
    message_out.last_subframe_epoch = latest_block.subframe_epoch;
    message_out.type = sat.type;
    message_out.dsm_id = sat.dsm_id;
    message_out.block_count = expected_blocks;
    message_out.byte_count = expected_blocks * OsnmaDsmBlock::SIZE_BYTES;

    for (int32_t block_index = 0; block_index < expected_blocks; ++block_index)
    {
        const int32_t dst_offset = block_index * OsnmaDsmBlock::SIZE_BYTES;

        for (int32_t j = 0; j < OsnmaDsmBlock::SIZE_BYTES; ++j)
        {
            message_out.data[dst_offset + j] =
                sat.blocks[block_index].data[j];
        }
    }

    sat.done = true;
    return true;
}
