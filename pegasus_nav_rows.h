// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <limits>
#include <optional>

#include "osnma_mack.h"
#include "osnma_types.h"

/*
    Pegasus navigation-row structures.

    Each structure below maps one-to-one to one row of the corresponding
    semicolon-separated Pegasus file:

        <prefix>_<system>_<nav_type>.eph
        <prefix>_<system>_<nav_type>.iono
        <prefix>_<system>_<nav_type>.dtime

    All week numbers are continuous GPS weeks including rollover. For
    Galileo data decoded from GST, GPS_WEEK = GST_WEEK + 1024.

    The fields named PRN use the Pegasus Galileo SVID convention 71..106.
    osnmalib continues to use Galileo PRNs 1..36 internally.

    RX_WEEK/RX_TOM is the time at which the row becomes available to
    Pegasus and is therefore the file synchronization key:
      - initial unauthenticated row: end of the page that completed the
        navigation object;
      - authenticated repetition: end of the page that completed the
        authentication event.

    Internally, osnmalib receives the transmission time of the first bit of
    each complete two-second Galileo I/NAV page.  RX_WEEK/RX_TOM is therefore
    that internal page epoch plus two seconds, with week rollover normalized.

    AUTH_WEEK/AUTH_TOM uses the same page-completion availability convention.

    TX_WEEK/TX_TOM preserves the original first-bit transmission/page epoch.

    CSV formatting is intentionally kept outside these structures:
      - floating-point values: %.17g
      - enums: decimal integers
      - bit fields and NAV_FINGERPRINT: quoted hexadecimal strings
      - unavailable values: empty CSV fields
*/

constexpr int32_t PEGASUS_INVALID_WEEK =
    std::numeric_limits<int32_t>::min();

constexpr double PEGASUS_INVALID_TOM =
    -std::numeric_limits<double>::max();

constexpr int32_t GALILEO_GST_TO_GPS_WEEK_OFFSET = 1024;

/*
    Galileo satellite-number convention used in Pegasus CSV/output rows.

    osnmalib uses the Galileo OSNMA PRN range 1..36 internally. Pegasus
    uses the receiver/team SVID convention 71..106 in every column named
    PRN (including RELATED_PRN in .osnmalog).
*/
constexpr int32_t GALILEO_PRN_TO_SVID_OFFSET = 70;

constexpr bool IsGalileoOsnmaPrn(int32_t prn)
{
    return prn >= 1 && prn <= 36;
}

constexpr int32_t GalileoPrnToPegasusSvid(int32_t prn)
{
    return IsGalileoOsnmaPrn(prn)
        ? prn + GALILEO_PRN_TO_SVID_OFFSET
        : prn;
}

/*
    Stable external values used by TARGET_TIME_SYSTEM in .dtime rows.

    The source time system is implied by the file name. For example, in an
    E_INAV.dtime file the source is GST. The broadcast polynomial is stored
    unchanged and represents SOURCE_TIME - TARGET_TIME.
*/
enum class PegasusTimeSystem : int32_t
{
    Utc = 0,
    Gps = 1,
    Galileo = 2,
    Glonass = 3,
    Beidou = 4,
    Qzss = 5,
    Navic = 6
};

/* One row of <prefix>_<system>_<nav_type>.eph. */
struct PegasusEphRow
{
    // "RX_WEEK";"RX_TOM";"PRN" (Galileo SVID 71..106)
    int32_t rx_week = PEGASUS_INVALID_WEEK;
    double rx_tom = PEGASUS_INVALID_TOM;
    int32_t prn = -1;

    // "AUTH_STATUS";"AUTH_REASON";"AUTH_WEEK";"AUTH_TOM"
    AuthState auth_status = AuthState::Unknown;
    AuthReason auth_reason = AuthReason::NotInitialized;
    int32_t auth_week = PEGASUS_INVALID_WEEK;
    double auth_tom = PEGASUS_INVALID_TOM;

    // "AUTH_ADKD";"AUTH_BITS";"NAV_FINGERPRINT"
    std::optional<OsnmaAdkd> auth_adkd{};
    std::int64_t auth_bits = 0;
    std::uint64_t nav_fingerprint = 0;

    // RINEX-equivalent satellite clock and ephemeris fields.
    // "TOC_WEEK";"TOC_TOM";"AF0";"AF1";"AF2"
    int32_t toc_week = PEGASUS_INVALID_WEEK;
    double toc_tom = PEGASUS_INVALID_TOM;
    double af0 = 0.0;
    double af1 = 0.0;
    double af2 = 0.0;

    // "IODNAV";"C_RS";"DELTA_N";"M_0"
    int32_t iodnav = -1;
    double c_rs = 0.0;
    double delta_n = 0.0;
    double m_0 = 0.0;

    // "C_UC";"ECCENTRICITY";"C_US";"SQRT_A"
    double c_uc = 0.0;
    double eccentricity = 0.0;
    double c_us = 0.0;
    double sqrt_a = 0.0;

    // "TOE_WEEK";"TOE";"C_IC";"OMEGA_0";"C_IS";"I_0"
    int32_t toe_week = PEGASUS_INVALID_WEEK;
    double toe = PEGASUS_INVALID_TOM;
    double c_ic = 0.0;
    double omega_0 = 0.0;
    double c_is = 0.0;
    double i_0 = 0.0;

    // "C_RC";"OMEGA";"OMEGA_DOT";"I_DOT"
    double c_rc = 0.0;
    double omega = 0.0;
    double omega_dot = 0.0;
    double i_dot = 0.0;

    // Bit fields are written as quoted hexadecimal strings in CSV.
    // "DATA_SOURCES";"SISA";"SV_HEALTH"
    std::uint32_t data_sources = 0;
    std::uint32_t sisa = 0; // Raw broadcast SISA index.
    std::uint32_t sv_health = 0;

    // "BGD_E5A_E1";"BGD_E5B_E1"
    double bgd_e5a_e1 = 0.0;
    double bgd_e5b_e1 = 0.0;

    // "TX_WEEK";"TX_TOM"
    int32_t tx_week = PEGASUS_INVALID_WEEK;
    double tx_tom = PEGASUS_INVALID_TOM;
};

/* One row of <prefix>_<system>_<nav_type>.iono. */
struct PegasusIonoRow
{
    // "RX_WEEK";"RX_TOM";"PRN" (Galileo SVID 71..106)
    int32_t rx_week = PEGASUS_INVALID_WEEK;
    double rx_tom = PEGASUS_INVALID_TOM;
    int32_t prn = -1;

    // Authentication metadata for the containing authenticated object.
    AuthState auth_status = AuthState::Unknown;
    AuthReason auth_reason = AuthReason::NotInitialized;
    int32_t auth_week = PEGASUS_INVALID_WEEK;
    double auth_tom = PEGASUS_INVALID_TOM;
    std::optional<OsnmaAdkd> auth_adkd{};
    std::int64_t auth_bits = 0;
    std::uint64_t nav_fingerprint = 0;

    // "AI0";"AI1";"AI2";"STORM_FLAGS"
    double ai0 = 0.0;
    double ai1 = 0.0;
    double ai2 = 0.0;
    std::uint8_t storm_flags = 0;

    // "TX_WEEK";"TX_TOM"
    int32_t tx_week = PEGASUS_INVALID_WEEK;
    double tx_tom = PEGASUS_INVALID_TOM;
};

/*
    One row of <prefix>_<system>_<nav_type>.dtime.

    A Galileo ADKD=4 object may generate two rows:
      - TARGET_TIME_SYSTEM=Utc for GST-UTC from WT6
      - TARGET_TIME_SYSTEM=Gps for GST-GPST (GGTO) from WT10
*/
struct PegasusDtimeRow
{
    // "RX_WEEK";"RX_TOM";"PRN" (Galileo SVID 71..106)
    int32_t rx_week = PEGASUS_INVALID_WEEK;
    double rx_tom = PEGASUS_INVALID_TOM;
    int32_t prn = -1;

    // Authentication metadata for the containing authenticated object.
    AuthState auth_status = AuthState::Unknown;
    AuthReason auth_reason = AuthReason::NotInitialized;
    int32_t auth_week = PEGASUS_INVALID_WEEK;
    double auth_tom = PEGASUS_INVALID_TOM;
    std::optional<OsnmaAdkd> auth_adkd{};
    std::int64_t auth_bits = 0;
    std::uint64_t nav_fingerprint = 0;

    // "TARGET_TIME_SYSTEM";"A0";"A1";"A2"
    PegasusTimeSystem target_time_system = PegasusTimeSystem::Utc;
    double a0 = 0.0;
    double a1 = 0.0;
    std::optional<double> a2{};

    // "REFERENCE_WEEK";"REFERENCE_TOM"
    int32_t reference_week = PEGASUS_INVALID_WEEK;
    double reference_tom = PEGASUS_INVALID_TOM;

    // "TX_WEEK";"TX_TOM"
    int32_t tx_week = PEGASUS_INVALID_WEEK;
    double tx_tom = PEGASUS_INVALID_TOM;
};
