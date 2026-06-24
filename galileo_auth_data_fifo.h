#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>

#include "GALDataStructures.h"
#include "galileo_nav_candidate.h"
#include "gnss_time.h"
#include "nav_signal_source.h"
#include "osnma_mack.h"
#include "osnma_types.h"
#include "pegasus_nav_rows.h"
#include "pegasus_log_rows.h"

/*
    One authenticated ADKD=0/12 CED/status object.

    The structure keeps both:
      - decoded Pegasus-compatible navigation structures, and
      - the exact authenticated 128-bit I/NAV logical words.

    This makes the output usable immediately while preserving enough raw data
    for diagnostics and independent decoding checks.
*/
struct GalileoAuthenticatedCedStatus
{
    GnssTime navigation_time{};
    GnssTime authentication_time{};

    // Reception epochs of the authenticated WT1 and WT5 are kept for
    // compatibility and for the WT5 NeQuick-G transmission epoch.
    GnssTime wt1_page_time{};
    GnssTime wt5_page_time{};

    // page_times[0..4] contain the selected WT1..WT5 page epochs.
    std::array<GnssTime, 5> page_times{};

    // Earliest epoch at which this exact WT1..WT5 combination was complete.
    // This is the RINEX ephemeris transmission time source.
    GnssTime ephemeris_transmission_time{};

    int32_t prn = -1;
    std::int64_t auth_bits = 0;
    std::uint64_t nav_fingerprint = 0;

    NavSignalSource source = NavSignalSource::Unknown;
    int32_t raw_source = 0;
    OsnmaAdkd authentication_adkd = OsnmaAdkd::Reserved;

    bool ephemeris_valid = false;
    bool ionosphere_valid = false;
    bool iodnav_consistent = false;
    bool svid_matches_prn = false;

    int32_t iodnav = -1;
    std::array<int32_t, 4> iodnav_by_word{};

    std::uint8_t sisa = 0;
    std::uint8_t e5b_shs = 0;
    std::uint8_t e1b_shs = 0;
    bool e5b_dvs = false;
    bool e1b_dvs = false;

    GALEphDecodedType ephemeris{};
    GALIonoDecodedType ionosphere{};

    // raw_words[0..4] contain WT1..WT5 respectively.
    std::array<std::array<std::uint8_t, GAL_INAV_BYTES>, 5> raw_words{};
};

/*
    One authenticated ADKD=4 timing object.

    utc contains the GST-UTC parameters from WT6. The GGTO fields contain the
    GST-GPS conversion parameters from WT10, which are not represented by the
    legacy GALTimeDecodedType structure.
*/
struct GalileoAuthenticatedTiming
{
    GnssTime navigation_time{};
    GnssTime authentication_time{};

    int32_t prn = -1;
    std::int64_t auth_bits = 0;
    std::uint64_t nav_fingerprint = 0;

    NavSignalSource source = NavSignalSource::Unknown;
    int32_t raw_source = 0;
    OsnmaAdkd authentication_adkd = OsnmaAdkd::InavTiming;

    bool utc_valid = false;
    bool ggto_valid = false;

    // Reception epochs of the authenticated WT6 (GST-UTC) and WT10
    // (GST-GPS/GGTO) words, used as RINEX STO transmission times.
    GnssTime wt6_page_time{};
    GnssTime wt10_page_time{};

    GALTimeDecodedType utc{};

    double a0g = DOUBLE_DONOTUSE;
    double a1g = DOUBLE_DONOTUSE;
    int32_t t0g = std::numeric_limits<int32_t>::min();
    int32_t wn0g = std::numeric_limits<int32_t>::min();

    std::array<std::uint8_t, GAL_INAV_BYTES> raw_wt6{};
    std::array<std::uint8_t, GAL_INAV_BYTES> raw_wt10{};
};

class AuthEphRecord
{
public:
    AuthEphRecord();

    GALEphDecodedType data{};
};

class AuthIonoRecord
{
public:
    AuthIonoRecord();

    GALIonoDecodedType data{};
};

class AuthTimeRecord
{
public:
    AuthTimeRecord();

    GALTimeDecodedType data{};
};

class GalileoInavDecoder
{
public:
    static bool DecodeCedStatus(const GalileoNavCandidate& candidate,
        const GnssTime& navigation_time,
        const GnssTime& authentication_time,
        std::int64_t auth_bits,
        std::uint64_t nav_fingerprint,
        NavSignalSource source,
        int32_t raw_source,
        GalileoAuthenticatedCedStatus& out);

    static bool DecodeTiming(const GalileoNavCandidate& candidate,
        const GnssTime& navigation_time,
        const GnssTime& authentication_time,
        std::int64_t auth_bits,
        std::uint64_t nav_fingerprint,
        NavSignalSource source,
        int32_t raw_source,
        GalileoAuthenticatedTiming& out);

    /*
        Build one-to-one Pegasus CSV row structures from authenticated
        diagnostic records. The output week numbers are continuous GPS weeks.
    */
    static bool MakePegasusEphRow(
        const GalileoAuthenticatedCedStatus& data,
        PegasusEphRow& out);

    static bool MakePegasusIonoRow(
        const GalileoAuthenticatedCedStatus& data,
        PegasusIonoRow& out);

    static int32_t MakePegasusDtimeRows(
        const GalileoAuthenticatedTiming& data,
        PegasusDtimeRow* out_rows,
        int32_t max_rows);

    static bool MakeReceivedPegasusEphRow(
        const GalileoNavCandidate& candidate,
        NavSignalSource source,
        int32_t raw_source,
        PegasusEphRow& out);

    static bool MakeReceivedPegasusIonoRow(
        const GalileoNavCandidate& candidate,
        PegasusIonoRow& out);

    static bool MakeReceivedPegasusDtimeRow(
        const GalileoNavCandidate& candidate,
        int32_t wt,
        PegasusDtimeRow& out);
};

class GalileoAuthDataFifo
{
public:
    void Reset();

    void PushCedStatus(const GalileoAuthenticatedCedStatus& data);
    void PushTiming(const GalileoAuthenticatedTiming& data);

    bool PopCedStatus(GalileoAuthenticatedCedStatus& data);
    bool PopTiming(GalileoAuthenticatedTiming& data);

    int32_t CedStatusCount() const;
    int32_t TimingCount() const;

    /*
        Row-level output. Each returned structure maps directly to one row of
        .eph, .iono or .dtime respectively.
    */
    bool PopPegasusEphRow(PegasusEphRow& row);
    bool PopPegasusIonoRow(PegasusIonoRow& row);
    bool PopPegasusDtimeRow(PegasusDtimeRow& row);

    int32_t PegasusEphRowCount() const;
    int32_t PegasusIonoRowCount() const;
    int32_t PegasusDtimeRowCount() const;

    void ObserveNavigation(const GalileoNavFeedObservation& observation,
        NavSignalSource source,
        int32_t raw_source);

    void PushLog(const PegasusLogRow& row);
    bool PopPegasusLogRow(PegasusLogRow& row);
    int32_t PegasusLogRowCount() const;

private:
    std::deque<GalileoAuthenticatedCedStatus> ced_status_;
    std::deque<GalileoAuthenticatedTiming> timing_;

    std::deque<PegasusEphRow> pegasus_eph_rows_;
    std::deque<PegasusIonoRow> pegasus_iono_rows_;
    std::deque<PegasusDtimeRow> pegasus_dtime_rows_;
    std::deque<PegasusLogRow> pegasus_log_rows_;

    static constexpr int32_t PEGASUS_MAX_PRN = 256;
    std::array<std::optional<std::uint64_t>, PEGASUS_MAX_PRN> last_rx_eph_{};
    std::array<std::optional<std::uint64_t>, PEGASUS_MAX_PRN> last_rx_iono_{};
    std::array<std::array<std::optional<std::uint64_t>, 2>, PEGASUS_MAX_PRN> last_rx_dtime_{};
    std::array<std::optional<std::uint64_t>, PEGASUS_MAX_PRN> last_auth_eph_{};
    std::array<std::optional<std::uint64_t>, PEGASUS_MAX_PRN> last_auth_iono_{};
    std::array<std::array<std::optional<std::uint64_t>, 2>, PEGASUS_MAX_PRN> last_auth_dtime_{};
};
