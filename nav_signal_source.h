// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>

enum class NavSignalSource : int32_t
{
    Unknown = 0,
    Freq1,
    Freq2,
    Freq3,
    Freq4,
    Freq5,
    Freq6,
    Freq7,
    Freq8,
    Freq9,
    Mixed
};
