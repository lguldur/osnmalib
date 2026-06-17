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


enum class NavTimingMode : int32_t
{
    Standard = 0,

    /*
        Official EUSPA/GSC CSV E1-B timing.

        Annex B gives the filename time as the first transmitted bit. The
        useful E1-B page/subframe grid is offset by one second, so page
        epochs must be assigned with floor((tow - 1) / 30) * 30.

        This mode is only for assigning received page epochs to their 30 s
        subframe. MAC lookup times are already subframe-boundary GST values
        and are not shifted again.
    */
    OfficialCsvE1B = 1
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
