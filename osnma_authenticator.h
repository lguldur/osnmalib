// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>

#include "galileo_inav_page_parts.h"
#include "osnma_engine.h"
#include "osnma_dsm_content.h"
#include "osnma_page_parser.h"
#include "osnma_subframe_assembler.h"
#include "osnma_types.h"

class OsnmaAuthenticator
{
public:
    static constexpr int32_t MAX_PRN = 256;

    explicit OsnmaAuthenticator() = default;

    void Reset();

    void SetNavTimingMode(NavTimingMode mode);
    NavTimingMode GetNavTimingMode() const;

    FeedResult FeedRawInavPage(int32_t prn,
        const std::uint8_t* even_128b,
        const std::uint8_t* odd_128b,
        const GnssTime& page_time,
        NavSignalSource source,
        int32_t raw_source,
        bool crc_ok = true);

    FeedResult FeedPageParts(const GalileoInavPageParts& page);

    Status GetStatus(int32_t prn, const GnssTime& now) const;

    const OsnmaEngine::Statistics& GetEngineStatistics() const;

    bool PopAuthenticatedCedStatus(GalileoAuthenticatedCedStatus& data);
    bool PopAuthenticatedTiming(GalileoAuthenticatedTiming& data);

    int32_t AuthenticatedCedStatusCount() const;
    int32_t AuthenticatedTimingCount() const;

    /* Direct one-row-per-record Pegasus output. */
    bool PopPegasusEphRow(PegasusEphRow& row);
    bool PopPegasusIonoRow(PegasusIonoRow& row);
    bool PopPegasusDtimeRow(PegasusDtimeRow& row);

    int32_t PegasusEphRowCount() const;
    int32_t PegasusIonoRowCount() const;
    int32_t PegasusDtimeRowCount() const;

    bool PopPegasusLogRow(PegasusLogRow& row);
    int32_t PegasusLogRowCount() const;
    void AddPegasusLogRow(const PegasusLogRow& row);

    bool SetMerkleRoot(const std::uint8_t* root_32_bytes);

    bool AddTrustedPublicKey(const OsnmaDsmPkr& public_key);

private:
    struct SatRecord
    {
        AuthState state = AuthState::Unknown;
        AuthReason reason = AuthReason::NoOsnmaData;

        GnssTime last_time{};
        bool has_time = false;

        NavSignalSource source = NavSignalSource::Unknown;
        int32_t raw_source = 0;
    };

private:
    bool IsValidPrn(int32_t prn) const;

private:
    std::array<SatRecord, MAX_PRN> sats_{};

    OsnmaPageParser parser_{};
    OsnmaSubframeAssembler assembler_{};
    OsnmaEngine engine_{};
};
