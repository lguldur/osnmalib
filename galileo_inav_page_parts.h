#pragma once

#include <cstddef>
#include <cstdint>

#include "gnss_time.h"
#include "nav_signal_source.h"

// Galileo I/NAV logical page sizes
static constexpr int32_t GAL_INAV_BITS = 128;
static constexpr int32_t GAL_INAV_BYTES = 16;

struct GalileoInavPageParts
{
    int32_t prn = -1;

    // Page reference epoch (GNSS time)
    GnssTime page_epoch{};

    bool crc_ok = false;

    NavSignalSource source = NavSignalSource::Unknown;
    int32_t native_source_code = 0;

    /*
    Packed Galileo I/NAV word image used by OSNMA authentication.

    This is a 128-bit software buffer.

    Bit-indexing convention used by GetBitMsb0():
        logical bit n is stored at:
            byte = n / 8
            mask = 0x80 >> (n % 8)

    Therefore:
        logical bit 0   = byte 0,  mask 0x80
        logical bit 127 = byte 15, mask 0x01
*/
    const std::uint8_t* even = nullptr; // 128 bits
    const std::uint8_t* odd  = nullptr; // 128 bits
};
