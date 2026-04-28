#pragma once

#include <cstdint>
#include "gnss_time.h"
#include "nav_signal_source.h"

enum class AuthState : int32_t
{
    Yes = 0,
    No = 1,
    Unknown = 2
};

enum class AuthReason : int32_t
{
    None = 0,
    NotInitialized,
    InvalidPrn,
    InvalidTime,
    InvalidFrameFormat,
    NoOsnmaData,
    WaitingForMoreFrames,
    WaitingForKey,
    IncompleteDsm,
    MissingNavData,
    AuthenticationExpired,
    StaleData,
    TimeInconsistency,
    MerkleVerificationFailed,
    PublicKeyVerificationFailed,
    SignatureVerificationFailed,
    TeslaChainVerificationFailed,
    MackVerificationFailed,
    BufferOverflow,
    UnsupportedMessage,
    InternalError
};

struct OsnmaConfig
{
    double auth_validity_s = 90.0;
    double partial_data_validity_s = 180.0;
    double negative_status_validity_s = 60.0;
};

struct Status
{
    AuthState state = AuthState::Unknown;
    AuthReason reason = AuthReason::NotInitialized;
    GnssTime event_time{};
    double age_s = 0.0;
    bool valid = false;

    NavSignalSource source = NavSignalSource::Unknown;
    int32_t native_source_code = 0;
};

struct FeedResult
{
    int32_t prn = -1;
    Status status{};
};
