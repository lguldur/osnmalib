#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "nav_signal_source.h"
#include "osnma_mack.h"
#include "osnma_types.h"
#include "pegasus_nav_rows.h"

/*
    One row of <prefix>_<system>_<nav_type>.log.

    These events identify anomalies that may be caused by RF interference,
    receiver/data loss, malformed input, or implementation/configuration
    problems.  The log deliberately reports observations; it never claims
    that interference was the proven cause.
*/
enum class PegasusLogSeverity : int32_t
{
    Information = 0,
    Warning = 1,
    Error = 2
};

enum class PegasusLogEvent : int32_t
{
    PageCrcFailed = 1,
    PageRejected = 2,
    PageParseFailed = 3,
    SubframeAssemblyFailed = 4,

    DsmDecodeFailed = 10,
    PublicKeyVerificationFailed = 11,
    KrootVerificationFailed = 12,
    TeslaInitializationFailed = 13,
    DisclosedKeyVerificationFailed = 14,

    MackParseFailed = 20,
    MackMacseqRejected = 21,
    MackTagVerificationFailed = 22,
    MackValidationFailed = 23,
    MissingNavigationData = 24,
    PendingMackExpired = 25,
    PendingMackOverwritten = 26,

    InputMalformedLine = 40,
    InputMalformedHex = 41,
    InputMissingE1bArray = 42,
    InputNullPage = 43,
    InputOutOfOrder = 44
};

struct PegasusLogRow
{
    // Continuous GPS week including rollover and receiver/event TOM.
    std::optional<int32_t> rx_week{};
    std::optional<double> rx_tom{};
    std::optional<int32_t> prn{};

    PegasusLogSeverity severity = PegasusLogSeverity::Warning;
    PegasusLogEvent event = PegasusLogEvent::PageRejected;

    std::optional<AuthReason> auth_reason{};
    std::optional<int32_t> stage{};
    std::optional<int32_t> wt{};
    std::optional<int32_t> dsm_id{};
    std::optional<int32_t> block_id{};
    std::optional<int32_t> tag_index{};
    std::optional<int32_t> ctr{};
    std::optional<int32_t> related_prn{};
    std::optional<OsnmaAdkd> adkd{};
    std::optional<int32_t> cop{};
    std::optional<std::int64_t> count{};

    std::optional<NavSignalSource> source{};
    std::optional<int32_t> raw_source{};

    std::string detail{};
};
