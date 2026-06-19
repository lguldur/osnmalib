#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <limits>

#include "GALDataStructures.h"
#include "galileo_nav_candidate.h"
#include "gnss_time.h"
#include "nav_signal_source.h"
#include "osnma_mack.h"
#include "osnma_types.h"

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
        Legacy standalone queues retained for source compatibility. They are
        not populated automatically by OsnmaEngine; new code should consume
        the combined authenticated records above so authentication metadata
        and the exact raw words remain attached to the decoded structures.
    */
    void PushEph(const GALEphDecodedType& eph);
    void PushIono(const GALIonoDecodedType& iono);
    void PushTime(const GALTimeDecodedType& time);

    bool PopEph(GALEphDecodedType& eph);
    bool PopIono(GALIonoDecodedType& iono);
    bool PopTime(GALTimeDecodedType& time);

    int32_t EphCount() const;
    int32_t IonoCount() const;
    int32_t TimeCount() const;

private:
    std::deque<GalileoAuthenticatedCedStatus> ced_status_;
    std::deque<GalileoAuthenticatedTiming> timing_;

    std::deque<AuthEphRecord> eph_;
    std::deque<AuthIonoRecord> iono_;
    std::deque<AuthTimeRecord> time_;
};
