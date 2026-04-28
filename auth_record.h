#pragma once

#include "gnss_time.h"
#include "nav_signal_source.h"
#include "osnma_types.h"

struct AuthRecord
{
    // When this status became valid
    GnssTime rx_time;

    // Ephemeris identity
    int32_t prn = -1;
    int32_t iod = -1;
    double toe = 0.0;

    // Optional diagnostic
    int32_t crc = 0;

    // Authentication result
    AuthState auth = AuthState::Unknown;
    AuthReason auth_reason = AuthReason::NotInitialized;

    // Signal origin
    NavSignalSource source = NavSignalSource::Unknown;
    int32_t raw_source = 0;
};
