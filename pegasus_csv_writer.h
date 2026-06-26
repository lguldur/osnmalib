// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>

#include "osnma_authenticator.h"
#include "osnma_raw_json_reader.h"

class PegasusCsvWriter
{
public:
    struct Result
    {
        std::string eph_filename;
        std::string iono_filename;
        std::string dtime_filename;
        std::string log_filename;

        int32_t eph_rows = 0;
        int32_t iono_rows = 0;
        int32_t dtime_rows = 0;
        int32_t log_rows = 0;
    };

    static bool Write(const char* prefix,
        OsnmaAuthenticator& authenticator,
        const OsnmaRawJsonReader::Stats& reader_stats,
        Result& result);
};
