// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>

struct GnssTime
{
    int32_t wn = 0;
    double tow = 0.0; // seconds
};

inline double DiffSeconds(const GnssTime& a, const GnssTime& b)
{
    return static_cast<double>(a.wn - b.wn) * 604800.0 + (a.tow - b.tow);
}

inline bool IsTimeValid(const GnssTime& t)
{
    return (t.wn >= 0) && (t.tow >= 0.0) && (t.tow < 604800.0);
}
