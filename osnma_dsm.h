#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "gnss_time.h"

enum class OsnmaDsmType : int32_t
{
    Unknown = 0,
    Kroot,
    Pkr
};

struct OsnmaNmaHeader
{
    uint8_t raw = 0;
};

struct OsnmaDsmHeader
{
    uint8_t raw = 0;

    int32_t dsm_id = -1;
    int32_t block_id = -1;
    OsnmaDsmType type = OsnmaDsmType::Unknown;
};

struct OsnmaDsmBlock
{
    int32_t prn = -1;
    GnssTime subframe_epoch{};

    OsnmaNmaHeader nma_header{};
    OsnmaDsmHeader dsm_header{};

    static constexpr int32_t SIZE_BYTES = 13;
    std::array<std::uint8_t, SIZE_BYTES> data{};
};

struct OsnmaDsmMessage
{
    int32_t prn = -1;
    GnssTime last_subframe_epoch{};

    OsnmaNmaHeader nma_header{};

    OsnmaDsmType type = OsnmaDsmType::Unknown;
    int32_t dsm_id = -1;

    static constexpr int32_t MAX_BLOCKS = 16;
    static constexpr int32_t BLOCK_BYTES = OsnmaDsmBlock::SIZE_BYTES;
    static constexpr int32_t MAX_BYTES = MAX_BLOCKS * BLOCK_BYTES;

    int32_t block_count = 0;
    int32_t byte_count = 0;

    std::array<std::uint8_t, MAX_BYTES> data{};
};

class OsnmaDsmAssembler
{
public:
    static constexpr int32_t MAX_PRN = 256;
    static constexpr int32_t MAX_BLOCKS = OsnmaDsmMessage::MAX_BLOCKS;

public:
    void Reset();

    bool FeedBlock(const OsnmaDsmBlock& block,
                   OsnmaDsmMessage& message_out);

    static OsnmaDsmHeader ParseDsmHeader(uint8_t raw);
    static OsnmaDsmType DsmTypeFromId(int32_t dsm_id);
    static int32_t NumberOfBlocks(OsnmaDsmType type, int32_t nb_value);

private:
    struct SatState
    {
        bool active = false;
        bool done = false;

        int32_t dsm_id = -1;
        OsnmaDsmType type = OsnmaDsmType::Unknown;

        std::array<bool, MAX_BLOCKS> received{};
        std::array<OsnmaDsmBlock, MAX_BLOCKS> blocks{};
    };

private:
    bool IsValidPrn(int32_t prn) const;
    bool BuildIfComplete(SatState& sat,
                         const OsnmaDsmBlock& latest_block,
                         OsnmaDsmMessage& message_out);

private:
    std::array<std::array<SatState, 16>, MAX_PRN> sats_{};
};
