#pragma once

#include <cstddef>
#include <cstdint>

#include "gnss_time.h"
#include "nav_signal_source.h"

// Galileo I/NAV logical page sizes
static constexpr int32_t GAL_INAV_BITS = 120;
static constexpr int32_t GAL_INAV_BYTES = 15;

struct GalileoInavPageParts
{
    int32_t prn = -1;

    // Page reference epoch (GNSS time)
    GnssTime page_epoch{};

    bool crc_ok = false;

    NavSignalSource source = NavSignalSource::Unknown;
    int32_t native_source_code = 0;

    // Packed bits (MSB-first)
    const std::uint8_t* even = nullptr; // 120 bits
    const std::uint8_t* odd  = nullptr; // 120 bits
};
