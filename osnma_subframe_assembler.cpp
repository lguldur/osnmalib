// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include "osnma_subframe_assembler.h"

#include <cmath>

void OsnmaSubframeAssembler::Reset()
{
    for (auto& sat : sats_)
        sat = SatAssembly{};
}

void OsnmaSubframeAssembler::SetNavTimingMode(NavTimingMode mode)
{
    timing_mode_ = mode;
}

NavTimingMode OsnmaSubframeAssembler::GetNavTimingMode() const
{
    return timing_mode_;
}

bool OsnmaSubframeAssembler::IsValidPrn(int32_t prn) const
{
    return prn > 0 && prn < MAX_PRN;
}

double OsnmaSubframeAssembler::PageReferenceTow(double tow,
    NavTimingMode mode)
{
    if (mode == NavTimingMode::OfficialCsvE1B)
        return tow - 1.0;

    return tow;
}

int32_t OsnmaSubframeAssembler::PageIndexFromTow(double tow) const
{
    double ref_tow = PageReferenceTow(tow, timing_mode_);

    while (ref_tow < 0.0)
        ref_tow += 604800.0;

    while (ref_tow >= 604800.0)
        ref_tow -= 604800.0;

    const double subframe_offset = std::fmod(ref_tow, 30.0);

    if (subframe_offset < 0.0)
        return -1;

    const int32_t index = static_cast<int32_t>(subframe_offset / 2.0);

    if (index < 0 || index >= PAGE_COUNT)
        return -1;

    return index;
}

GnssTime OsnmaSubframeAssembler::SubframeEpochFromTime(const GnssTime& t) const
{
    GnssTime out = t;

    double ref_tow = PageReferenceTow(t.tow, timing_mode_);

    while (ref_tow < 0.0)
    {
        ref_tow += 604800.0;
        --out.wn;
    }

    while (ref_tow >= 604800.0)
    {
        ref_tow -= 604800.0;
        ++out.wn;
    }

    out.tow = std::floor(ref_tow / 30.0) * 30.0;
    return out;
}

bool OsnmaSubframeAssembler::SameSubframe(const GnssTime& a,
                                          const GnssTime& b) const
{
    return (a.wn == b.wn) && (std::fabs(a.tow - b.tow) < 0.001);
}

bool OsnmaSubframeAssembler::FeedParsedPage(const ParsedPage& page,
                                            OsnmaSubframe& subframe_out,
                                            AuthReason& reason_out)
{
    subframe_out = OsnmaSubframe{};

    const int32_t prn = page.page.prn;

    if (!IsValidPrn(prn))
    {
        reason_out = AuthReason::InvalidPrn;
        return false;
    }

    if (!page.has_osnma)
    {
        reason_out = AuthReason::NoOsnmaData;
        return false;
    }

    const int32_t page_index = PageIndexFromTow(page.page.page_epoch.tow);

    if (page_index < 0)
    {
        reason_out = AuthReason::InvalidTime;
        return false;
    }

    const GnssTime subframe_epoch = SubframeEpochFromTime(page.page.page_epoch);

    SatAssembly& sat = sats_[static_cast<std::size_t>(prn)];

    if (!sat.active || !SameSubframe(sat.subframe_epoch, subframe_epoch))
    {
        sat = SatAssembly{};
        sat.active = true;
        sat.subframe_epoch = subframe_epoch;
    }

    const int32_t hkroot_byte = page_index;
    sat.hkroot[hkroot_byte] = page.hkroot_chunk[0];

    const int32_t mack_byte = page_index * 4;
    sat.mack[mack_byte + 0] = page.mack_chunk[0];
    sat.mack[mack_byte + 1] = page.mack_chunk[1];
    sat.mack[mack_byte + 2] = page.mack_chunk[2];
    sat.mack[mack_byte + 3] = page.mack_chunk[3];

    sat.received_mask |= (1 << page_index);

    const int32_t full_mask = (1 << PAGE_COUNT) - 1;

    if ((sat.received_mask & full_mask) != full_mask)
    {
        reason_out = AuthReason::WaitingForMoreFrames;
        return false;
    }

    subframe_out.prn = prn;
    subframe_out.subframe_epoch = sat.subframe_epoch;
    subframe_out.hkroot = sat.hkroot;
    subframe_out.mack = sat.mack;

    reason_out = AuthReason::WaitingForKey;
    return true;
}
