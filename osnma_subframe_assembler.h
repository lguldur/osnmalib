#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "gnss_time.h"
#include "osnma_page_parser.h"
#include "osnma_types.h"

struct OsnmaSubframe
{
    int32_t prn = -1;
    GnssTime subframe_epoch{};

    static constexpr int32_t PAGE_COUNT = 15;

    static constexpr int32_t HKROOT_BITS = 120;
    static constexpr int32_t HKROOT_BYTES = 15;

    static constexpr int32_t MACK_BITS = 480;
    static constexpr int32_t MACK_BYTES = 60;

    std::array<std::uint8_t, HKROOT_BYTES> hkroot{};
    std::array<std::uint8_t, MACK_BYTES> mack{};
};

class OsnmaSubframeAssembler
{
public:
    static constexpr int32_t MAX_PRN = 256;
    static constexpr int32_t PAGE_COUNT = 15;

public:
    void Reset();

    void SetNavTimingMode(NavTimingMode mode);
    NavTimingMode GetNavTimingMode() const;

    bool FeedParsedPage(const ParsedPage& page,
                        OsnmaSubframe& subframe_out,
                        AuthReason& reason_out);

private:
    struct SatAssembly
    {
        bool active = false;
        GnssTime subframe_epoch{};

        int32_t received_mask = 0;

        std::array<std::uint8_t, OsnmaSubframe::HKROOT_BYTES> hkroot{};
        std::array<std::uint8_t, OsnmaSubframe::MACK_BYTES> mack{};
    };

private:
    bool IsValidPrn(int32_t prn) const;
    int32_t PageIndexFromTow(double tow) const;
    GnssTime SubframeEpochFromTime(const GnssTime& t) const;
    static double PageReferenceTow(double tow, NavTimingMode mode);

    bool SameSubframe(const GnssTime& a, const GnssTime& b) const;

private:
    std::array<SatAssembly, MAX_PRN> sats_{};
    NavTimingMode timing_mode_ = NavTimingMode::Standard;
};
