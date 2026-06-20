#include "galileo_auth_data_fifo.h"

#include <cmath>
#include <cstring>
#include <limits>
#include <numbers>

#include "osnma_bit_utils.h"

namespace
{
    constexpr unsigned long UNKNOWN_ULONG =
        static_cast<unsigned long>(0x80000000u);

    constexpr unsigned long GAL_SOURCE_INAV = 1u;
    constexpr unsigned char GAL_SOURCE_INAV_U8 = 1u;

    // RINEX 3.05 Galileo data-source field for an I/NAV message decoded
    // from E1-B, with clock parameters valid for the E5b/E1 pair:
    //   bit 0 = I/NAV E1-B
    //   bit 9 = af0-af2, Toc and SISA valid for E5b/E1
    constexpr unsigned long GAL_RINEX_DATA_SOURCES_INAV_E1B =
        (1u << 0) | (1u << 9);

    double ScaleSigned(const std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count,
        int32_t binary_exponent)
    {
        return std::ldexp(
            static_cast<double>(GetSignedBits64Msb0(data,
                first_bit,
                bit_count)),
            binary_exponent);
    }

    double ScaleUnsigned(const std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count,
        int32_t binary_exponent)
    {
        return std::ldexp(
            static_cast<double>(GetUnsignedBits64Msb0(data,
                first_bit,
                bit_count)),
            binary_exponent);
    }

    double ScaleSignedSemicircles(const std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count,
        int32_t binary_exponent)
    {
        return ScaleSigned(data,
            first_bit,
            bit_count,
            binary_exponent) * std::numbers::pi_v<double>;
    }

    int32_t ResolveTruncatedWeek(int32_t reference_week,
        int32_t truncated_week,
        int32_t bit_count)
    {
        if (reference_week < 0 || bit_count <= 0 || bit_count >= 31)
            return truncated_week;

        const int32_t period = 1 << bit_count;
        const int32_t mask = period - 1;

        int32_t candidate =
            (reference_week & ~mask) | (truncated_week & mask);

        const int32_t half_period = period / 2;

        if ((candidate - reference_week) > half_period)
            candidate -= period;
        else if ((reference_week - candidate) > half_period)
            candidate += period;

        return candidate;
    }

    int32_t ResolveWeekForTow(const GnssTime& reference,
        double tow)
    {
        int32_t week = reference.wn;

        if (!IsTimeValid(reference))
            return week;

        const double dt = tow - reference.tow;

        if (dt > 302400.0)
            --week;
        else if (dt < -302400.0)
            ++week;

        return week;
    }

    std::uint32_t PackRinexHealth(std::uint8_t e5b_shs,
        std::uint8_t e1b_shs,
        bool e5b_dvs,
        bool e1b_dvs)
    {
        /*
            RINEX 3.05 Galileo SV-health bit allocation:

                bit 0    = E1-B DVS
                bits 1-2 = E1-B SHS
                bits 3-5 = E5a fields (not available from I/NAV here)
                bit 6    = E5b DVS
                bits 7-8 = E5b SHS
        */
        return
            (e1b_dvs ? (1u << 0) : 0u) |
            ((static_cast<std::uint32_t>(e1b_shs) & 0x03u) << 1) |
            (e5b_dvs ? (1u << 6) : 0u) |
            ((static_cast<std::uint32_t>(e5b_shs) & 0x03u) << 7);
    }

    bool IsAllOnes(std::uint64_t value,
        int32_t bit_count)
    {
        if (bit_count <= 0 || bit_count > 64)
            return false;

        if (bit_count == 64)
            return value == std::numeric_limits<std::uint64_t>::max();

        const std::uint64_t mask =
            (std::uint64_t{1} << bit_count) - 1u;

        return value == mask;
    }

    constexpr std::uint64_t FNV_OFFSET = 14695981039346656037ull;
    constexpr std::uint64_t FNV_PRIME = 1099511628211ull;

    void HashByte(std::uint64_t& hash, std::uint8_t value)
    {
        hash ^= value;
        hash *= FNV_PRIME;
    }

    void HashInt32(std::uint64_t& hash, int32_t value)
    {
        const std::uint32_t v = static_cast<std::uint32_t>(value);
        HashByte(hash, static_cast<std::uint8_t>((v >> 24) & 0xFFu));
        HashByte(hash, static_cast<std::uint8_t>((v >> 16) & 0xFFu));
        HashByte(hash, static_cast<std::uint8_t>((v >> 8) & 0xFFu));
        HashByte(hash, static_cast<std::uint8_t>(v & 0xFFu));
    }

    void HashBits(std::uint64_t& hash,
        const std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count)
    {
        if (data == nullptr || first_bit < 0 || bit_count <= 0)
            return;

        std::uint8_t packed = 0;
        int32_t packed_bits = 0;

        for (int32_t i = 0; i < bit_count; ++i)
        {
            packed = static_cast<std::uint8_t>(packed << 1);
            if (GetBitMsb0(data, first_bit + i))
                packed = static_cast<std::uint8_t>(packed | 1u);

            ++packed_bits;
            if (packed_bits == 8)
            {
                HashByte(hash, packed);
                packed = 0;
                packed_bits = 0;
            }
        }

        if (packed_bits != 0)
        {
            packed = static_cast<std::uint8_t>(packed << (8 - packed_bits));
            HashByte(hash, packed);
        }
    }

    std::uint64_t EphFingerprint(const std::uint8_t* wt1,
        const std::uint8_t* wt2,
        const std::uint8_t* wt3,
        const std::uint8_t* wt4,
        const std::uint8_t* wt5,
        int32_t prn)
    {
        std::uint64_t hash = FNV_OFFSET;
        HashInt32(hash, prn);
        HashBits(hash, wt1, 0, 128);
        HashBits(hash, wt2, 0, 128);
        HashBits(hash, wt3, 0, 128);
        HashBits(hash, wt4, 0, 128);
        // Only WT5 fields represented in .eph: BGD and health/DVS.
        HashBits(hash, wt5, 47, 26);
        return hash;
    }

    std::uint64_t IonoFingerprint(const std::uint8_t* wt5,
        int32_t prn)
    {
        std::uint64_t hash = FNV_OFFSET;
        HashInt32(hash, prn);
        // NeQuick-G coefficients and five regional disturbance flags.
        HashBits(hash, wt5, 6, 41);
        return hash;
    }

    std::uint64_t DtimeFingerprint(const std::uint8_t* word,
        int32_t wt,
        int32_t prn)
    {
        std::uint64_t hash = FNV_OFFSET;
        HashInt32(hash, prn);
        HashInt32(hash, wt);

        if (wt == GAL_WT6)
        {
            // GST-UTC A0/A1 plus T0/WN0. Leap-second fields are excluded.
            HashBits(hash, word, 6, 56);
            HashBits(hash, word, 70, 16);
        }
        else if (wt == GAL_WT10)
        {
            // GGTO A0G/A1G/T0G/WN0G.
            HashBits(hash, word, 86, 42);
        }

        return hash;
    }

    bool ValidPegasusPrn(int32_t prn)
    {
        return prn > 0 && prn < 256;
    }
}

AuthEphRecord::AuthEphRecord()
{
    data = GALEphDecodedType{};

    data.messageid = GAL_EPHEM_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVN = UNKNOWN_ULONG;
    data.Source = UNKNOWN_ULONG;

    data.Toc = INT_DONOTUSE;
    data.af2 = DOUBLE_DONOTUSE;
    data.af1 = DOUBLE_DONOTUSE;
    data.af0 = DOUBLE_DONOTUSE;
    data.af0_1 = DOUBLE_DONOTUSE;

    data.WNToc = UNKNOWN_ULONG;
    data.WNToe = UNKNOWN_ULONG;
    data.IODNav = UNKNOWN_ULONG;

    data.Crs = DOUBLE_DONOTUSE;
    data.DeltaN = DOUBLE_DONOTUSE;
    data.M0 = DOUBLE_DONOTUSE;
    data.Cuc = DOUBLE_DONOTUSE;
    data.Ecc = DOUBLE_DONOTUSE;
    data.Cus = DOUBLE_DONOTUSE;
    data.sqrtA = DOUBLE_DONOTUSE;
    data.Toe = INT_DONOTUSE;
    data.Cic = DOUBLE_DONOTUSE;
    data.Omega0 = DOUBLE_DONOTUSE;
    data.Cis = DOUBLE_DONOTUSE;
    data.i0 = DOUBLE_DONOTUSE;
    data.Crc = DOUBLE_DONOTUSE;
    data.Omega = DOUBLE_DONOTUSE;
    data.OmegaDot = DOUBLE_DONOTUSE;
    data.IDot = DOUBLE_DONOTUSE;

    data.HealthAndSisaInBinary = true;

    data.Health_OSSOL = UNKNOWN_ULONG;
    data.Health_PRS = UNKNOWN_ULONG;
    data.SISA_L1E5a = UNKNOWN_ULONG;
    data.SISA_L1E5b = UNKNOWN_ULONG;
    data.SISA_L1AE6A = UNKNOWN_ULONG;

    data.DataSources = UNKNOWN_ULONG;
    data.SISA = UNKNOWN_ULONG;
    data.SVHealth = UNKNOWN_ULONG;

    data.BGD_L1E5a = DOUBLE_DONOTUSE;
    data.BGD_L1E5b = DOUBLE_DONOTUSE;
    data.BGD_L1AE6A = DOUBLE_DONOTUSE;

    data.CNAVEncrypt = UNKNOWN_ULONG;
    data.SISA_used = UNKNOWN_ULONG;

    data.CRC = INT_DONOTUSE;
}

AuthIonoRecord::AuthIonoRecord()
{
    data = GALIonoDecodedType{};

    data.messageid = GAL_IONO_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVID = static_cast<unsigned char>(0);
    data.Source = static_cast<unsigned char>(0);

    data.ai0 = DOUBLE_DONOTUSE;
    data.ai1 = DOUBLE_DONOTUSE;
    data.ai2 = DOUBLE_DONOTUSE;

    data.StormFlags = static_cast<unsigned char>(0);
}

AuthTimeRecord::AuthTimeRecord()
{
    data = GALTimeDecodedType{};

    data.messageid = GAL_TIME_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVID = static_cast<unsigned char>(0);
    data.Source = static_cast<unsigned char>(0);

    data.a0 = DOUBLE_DONOTUSE;
    data.a1 = DOUBLE_DONOTUSE;

    data.T0_UTC = std::numeric_limits<int>::min();
    data.WN0_UTC = std::numeric_limits<int>::min();
    data.WN_LSF = std::numeric_limits<int>::min();
    data.DeltaT_LSF = std::numeric_limits<int>::min();
    data.DeltaT_LS = std::numeric_limits<int>::min();
    data.DN_LSF = std::numeric_limits<int>::min();
}

bool GalileoInavDecoder::DecodeCedStatus(
    const GalileoNavCandidate& candidate,
    const GnssTime& navigation_time,
    const GnssTime& authentication_time,
    std::int64_t auth_bits,
    std::uint64_t nav_fingerprint,
    NavSignalSource source,
    int32_t raw_source,
    GalileoAuthenticatedCedStatus& out)
{
    out = GalileoAuthenticatedCedStatus{};

    if (!candidate.HasCedData() || candidate.prn <= 0)
        return false;

    const std::uint8_t* wt1 = candidate.words[GAL_WT1].even.data();
    const std::uint8_t* wt2 = candidate.words[GAL_WT2].even.data();
    const std::uint8_t* wt3 = candidate.words[GAL_WT3].even.data();
    const std::uint8_t* wt4 = candidate.words[GAL_WT4].even.data();
    const std::uint8_t* wt5 = candidate.words[GAL_WT5].even.data();

    out.navigation_time = navigation_time;
    out.authentication_time = authentication_time;
    out.wt1_page_time = candidate.words[GAL_WT1].page_epoch;
    out.wt5_page_time = candidate.words[GAL_WT5].page_epoch;

    for (int32_t wt = GAL_WT1; wt <= GAL_WT5; ++wt)
        out.page_times[static_cast<std::size_t>(wt - GAL_WT1)] =
            candidate.words[wt].page_epoch;

    if (candidate.has_ced_complete_time &&
        IsTimeValid(candidate.ced_complete_time))
    {
        out.ephemeris_transmission_time =
            candidate.ced_complete_time;
    }
    else
    {
        // Defensive fallback for manually-created candidates used by callers
        // or tests that predate ced_complete_time tracking.
        GnssTime latest = candidate.words[GAL_WT1].page_epoch;
        for (int32_t wt = GAL_WT2; wt <= GAL_WT5; ++wt)
        {
            const GnssTime& epoch = candidate.words[wt].page_epoch;
            if (IsTimeValid(epoch) &&
                (!IsTimeValid(latest) || DiffSeconds(epoch, latest) > 0.0))
            {
                latest = epoch;
            }
        }
        out.ephemeris_transmission_time = latest;
    }

    out.prn = candidate.prn;
    out.auth_bits = auth_bits;
    out.nav_fingerprint = nav_fingerprint;
    out.source = source;
    out.raw_source = raw_source;

    std::memcpy(out.raw_words[0].data(), wt1, GAL_INAV_BYTES);
    std::memcpy(out.raw_words[1].data(), wt2, GAL_INAV_BYTES);
    std::memcpy(out.raw_words[2].data(), wt3, GAL_INAV_BYTES);
    std::memcpy(out.raw_words[3].data(), wt4, GAL_INAV_BYTES);
    std::memcpy(out.raw_words[4].data(), wt5, GAL_INAV_BYTES);

    for (int32_t i = 0; i < 4; ++i)
    {
        out.iodnav_by_word[i] =
            static_cast<int32_t>(GetUnsignedBits64Msb0(
                candidate.words[GAL_WT1 + i].even.data(),
                6,
                10));
    }

    out.iodnav = out.iodnav_by_word[0];
    out.iodnav_consistent =
        out.iodnav_by_word[1] == out.iodnav &&
        out.iodnav_by_word[2] == out.iodnav &&
        out.iodnav_by_word[3] == out.iodnav;

    const int32_t decoded_svid =
        static_cast<int32_t>(GetUnsignedBits64Msb0(wt4, 16, 6));

    out.svid_matches_prn = (decoded_svid == candidate.prn);
    out.ephemeris_valid =
        out.iodnav_consistent && out.svid_matches_prn;

    AuthEphRecord eph_record;
    GALEphDecodedType& eph = eph_record.data;

    eph.MessageWeek = navigation_time.wn;
    eph.MessageTime = navigation_time.tow;
    eph.SVN = static_cast<unsigned long>(decoded_svid);

    /*
        Source in the legacy structure denotes the navigation message family.
        This library currently decodes I/NAV only, so 1 is used consistently.
        The exact receiver signal/source is preserved separately in the
        combined authenticated structure.
    */
    eph.Source = GAL_SOURCE_INAV;

    eph.IODNav = static_cast<unsigned long>(out.iodnav);

    eph.Toe = static_cast<long>(
        GetUnsignedBits64Msb0(wt1, 16, 14) * 60u);
    eph.WNToe = static_cast<unsigned long>(
        ResolveWeekForTow(navigation_time,
            static_cast<double>(eph.Toe)));

    eph.M0 = ScaleSignedSemicircles(wt1, 30, 32, -31);
    eph.Ecc = ScaleUnsigned(wt1, 62, 32, -33);
    eph.sqrtA = ScaleUnsigned(wt1, 94, 32, -19);

    eph.Omega0 = ScaleSignedSemicircles(wt2, 16, 32, -31);
    eph.i0 = ScaleSignedSemicircles(wt2, 48, 32, -31);
    eph.Omega = ScaleSignedSemicircles(wt2, 80, 32, -31);
    eph.IDot = ScaleSignedSemicircles(wt2, 112, 14, -43);

    eph.OmegaDot = ScaleSignedSemicircles(wt3, 16, 24, -43);
    eph.DeltaN = ScaleSignedSemicircles(wt3, 40, 16, -43);
    eph.Cuc = ScaleSigned(wt3, 56, 16, -29);
    eph.Cus = ScaleSigned(wt3, 72, 16, -29);
    eph.Crc = ScaleSigned(wt3, 88, 16, -5);
    eph.Crs = ScaleSigned(wt3, 104, 16, -5);

    out.sisa = static_cast<std::uint8_t>(
        GetUnsignedBits64Msb0(wt3, 120, 8));

    eph.Cic = ScaleSigned(wt4, 22, 16, -29);
    eph.Cis = ScaleSigned(wt4, 38, 16, -29);

    eph.Toc = static_cast<long>(
        GetUnsignedBits64Msb0(wt4, 54, 14) * 60u);
    eph.WNToc = static_cast<unsigned long>(
        ResolveWeekForTow(navigation_time,
            static_cast<double>(eph.Toc)));

    eph.af0 = ScaleSigned(wt4, 68, 31, -34);
    eph.af1 = ScaleSigned(wt4, 99, 21, -46);
    eph.af2 = ScaleSigned(wt4, 120, 6, -59);

    const double bgd_e1_e5a =
        ScaleSigned(wt5, 47, 10, -32);
    const double bgd_e1_e5b =
        ScaleSigned(wt5, 57, 10, -32);

    out.e5b_shs = static_cast<std::uint8_t>(
        GetUnsignedBits64Msb0(wt5, 67, 2));
    out.e1b_shs = static_cast<std::uint8_t>(
        GetUnsignedBits64Msb0(wt5, 69, 2));
    out.e5b_dvs = GetBitMsb0(wt5, 71);
    out.e1b_dvs = GetBitMsb0(wt5, 72);

    eph.HealthAndSisaInBinary = true;
    eph.DataSources = GAL_RINEX_DATA_SOURCES_INAV_E1B;
    eph.SISA = static_cast<unsigned long>(out.sisa);
    eph.SVHealth = static_cast<unsigned long>(
        PackRinexHealth(out.e5b_shs,
            out.e1b_shs,
            out.e5b_dvs,
            out.e1b_dvs));

    eph.BGD_L1E5a = bgd_e1_e5a;
    eph.BGD_L1E5b = bgd_e1_e5b;
    eph.CRC = CRC_OK;

    out.ephemeris = eph;

    AuthIonoRecord iono_record;
    GALIonoDecodedType& iono = iono_record.data;

    iono.MessageWeek = navigation_time.wn;
    iono.MessageTime = navigation_time.tow;
    iono.SVID = static_cast<unsigned char>(candidate.prn);
    iono.Source = GAL_SOURCE_INAV_U8;

    iono.ai0 = ScaleUnsigned(wt5, 6, 11, -2);
    iono.ai1 = ScaleSigned(wt5, 17, 11, -8);
    iono.ai2 = ScaleSigned(wt5, 28, 14, -15);

    std::uint8_t storm_flags = 0;

    for (int32_t region = 0; region < 5; ++region)
    {
        if (GetBitMsb0(wt5, 42 + region))
        {
            storm_flags |= static_cast<std::uint8_t>(
                1u << (4 - region));
        }
    }

    iono.StormFlags = storm_flags;

    out.ionosphere = iono;
    out.ionosphere_valid = true;

    return true;
}

bool GalileoInavDecoder::DecodeTiming(
    const GalileoNavCandidate& candidate,
    const GnssTime& navigation_time,
    const GnssTime& authentication_time,
    std::int64_t auth_bits,
    std::uint64_t nav_fingerprint,
    NavSignalSource source,
    int32_t raw_source,
    GalileoAuthenticatedTiming& out)
{
    out = GalileoAuthenticatedTiming{};

    if (!candidate.HasTimingData() || candidate.prn <= 0)
        return false;

    const std::uint8_t* wt6 = candidate.words[GAL_WT6].even.data();
    const std::uint8_t* wt10 = candidate.words[GAL_WT10].even.data();

    out.navigation_time = navigation_time;
    out.authentication_time = authentication_time;
    out.wt6_page_time = candidate.words[GAL_WT6].page_epoch;
    out.wt10_page_time = candidate.words[GAL_WT10].page_epoch;
    out.prn = candidate.prn;
    out.auth_bits = auth_bits;
    out.nav_fingerprint = nav_fingerprint;
    out.source = source;
    out.raw_source = raw_source;

    std::memcpy(out.raw_wt6.data(), wt6, GAL_INAV_BYTES);
    std::memcpy(out.raw_wt10.data(), wt10, GAL_INAV_BYTES);

    AuthTimeRecord time_record;
    GALTimeDecodedType& utc = time_record.data;

    utc.MessageWeek = navigation_time.wn;
    utc.MessageTime = navigation_time.tow;
    utc.SVID = static_cast<unsigned char>(candidate.prn);
    utc.Source = GAL_SOURCE_INAV_U8;

    utc.a0 = ScaleSigned(wt6, 6, 32, -30);
    utc.a1 = ScaleSigned(wt6, 38, 24, -50);
    utc.DeltaT_LS = static_cast<int32_t>(
        GetSignedBits64Msb0(wt6, 62, 8));
    utc.T0_UTC = static_cast<int32_t>(
        GetUnsignedBits64Msb0(wt6, 70, 8) * 3600u);
    utc.WN0_UTC = ResolveTruncatedWeek(navigation_time.wn,
        static_cast<int32_t>(GetUnsignedBits64Msb0(wt6, 78, 8)),
        8);
    utc.WN_LSF = ResolveTruncatedWeek(navigation_time.wn,
        static_cast<int32_t>(GetUnsignedBits64Msb0(wt6, 86, 8)),
        8);
    utc.DN_LSF = static_cast<int32_t>(
        GetUnsignedBits64Msb0(wt6, 94, 3));
    utc.DeltaT_LSF = static_cast<int32_t>(
        GetSignedBits64Msb0(wt6, 97, 8));

    out.utc = utc;
    out.utc_valid = true;

    const std::uint64_t raw_a0g =
        GetUnsignedBits64Msb0(wt10, 86, 16);
    const std::uint64_t raw_a1g =
        GetUnsignedBits64Msb0(wt10, 102, 12);
    const std::uint64_t raw_t0g =
        GetUnsignedBits64Msb0(wt10, 114, 8);
    const std::uint64_t raw_wn0g =
        GetUnsignedBits64Msb0(wt10, 122, 6);

    const bool ggto_not_available =
        IsAllOnes(raw_a0g, 16) &&
        IsAllOnes(raw_a1g, 12) &&
        IsAllOnes(raw_t0g, 8) &&
        IsAllOnes(raw_wn0g, 6);

    if (!ggto_not_available)
    {
        out.a0g = ScaleSigned(wt10, 86, 16, -35);
        out.a1g = ScaleSigned(wt10, 102, 12, -51);
        out.t0g = static_cast<int32_t>(raw_t0g * 3600u);
        out.wn0g = ResolveTruncatedWeek(navigation_time.wn,
            static_cast<int32_t>(raw_wn0g),
            6);
        out.ggto_valid = true;
    }

    return true;
}


bool GalileoInavDecoder::MakePegasusEphRow(
    const GalileoAuthenticatedCedStatus& data,
    PegasusEphRow& out)
{
    out = PegasusEphRow{};

    if (!data.ephemeris_valid || data.prn <= 0)
        return false;

    const GALEphDecodedType& eph = data.ephemeris;

    const auto gps_week = [](int32_t gst_week) -> int32_t
    {
        return gst_week + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    };

    out.rx_week = gps_week(data.ephemeris_transmission_time.wn);
    out.rx_tom = data.ephemeris_transmission_time.tow;
    out.prn = data.prn;

    out.auth_status = AuthState::Yes;
    out.auth_reason = AuthReason::None;
    out.auth_week = gps_week(data.authentication_time.wn);
    out.auth_tom = data.authentication_time.tow;
    out.auth_adkd = data.authentication_adkd;
    out.auth_bits = data.auth_bits;
    out.nav_fingerprint = EphFingerprint(
        data.raw_words[0].data(),
        data.raw_words[1].data(),
        data.raw_words[2].data(),
        data.raw_words[3].data(),
        data.raw_words[4].data(),
        data.prn);

    out.toc_week = gps_week(static_cast<int32_t>(eph.WNToc));
    out.toc_tom = static_cast<double>(eph.Toc);
    out.af0 = eph.af0;
    out.af1 = eph.af1;
    out.af2 = eph.af2;

    out.iodnav = static_cast<int32_t>(eph.IODNav);
    out.c_rs = eph.Crs;
    out.delta_n = eph.DeltaN;
    out.m_0 = eph.M0;
    out.c_uc = eph.Cuc;
    out.eccentricity = eph.Ecc;
    out.c_us = eph.Cus;
    out.sqrt_a = eph.sqrtA;

    out.toe_week = gps_week(static_cast<int32_t>(eph.WNToe));
    out.toe = static_cast<double>(eph.Toe);
    out.c_ic = eph.Cic;
    out.omega_0 = eph.Omega0;
    out.c_is = eph.Cis;
    out.i_0 = eph.i0;
    out.c_rc = eph.Crc;
    out.omega = eph.Omega;
    out.omega_dot = eph.OmegaDot;
    out.i_dot = eph.IDot;

    out.data_sources = static_cast<std::uint32_t>(eph.DataSources);
    out.sisa = static_cast<std::uint32_t>(data.sisa);

    out.sv_health = static_cast<std::uint32_t>(eph.SVHealth);
    out.bgd_e5a_e1 = eph.BGD_L1E5a;
    out.bgd_e5b_e1 = eph.BGD_L1E5b;

    out.tx_week = gps_week(data.ephemeris_transmission_time.wn);
    out.tx_tom = data.ephemeris_transmission_time.tow;

    return true;
}

bool GalileoInavDecoder::MakePegasusIonoRow(
    const GalileoAuthenticatedCedStatus& data,
    PegasusIonoRow& out)
{
    out = PegasusIonoRow{};

    if (!data.ionosphere_valid || data.prn <= 0)
        return false;

    const auto gps_week = [](int32_t gst_week) -> int32_t
    {
        return gst_week + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    };

    out.rx_week = gps_week(data.wt5_page_time.wn);
    out.rx_tom = data.wt5_page_time.tow;
    out.prn = data.prn;

    out.auth_status = AuthState::Yes;
    out.auth_reason = AuthReason::None;
    out.auth_week = gps_week(data.authentication_time.wn);
    out.auth_tom = data.authentication_time.tow;
    out.auth_adkd = data.authentication_adkd;
    out.auth_bits = data.auth_bits;
    out.nav_fingerprint = IonoFingerprint(
        data.raw_words[4].data(),
        data.prn);

    out.ai0 = data.ionosphere.ai0;
    out.ai1 = data.ionosphere.ai1;
    out.ai2 = data.ionosphere.ai2;
    out.storm_flags = data.ionosphere.StormFlags;

    out.tx_week = gps_week(data.wt5_page_time.wn);
    out.tx_tom = data.wt5_page_time.tow;

    return true;
}

int32_t GalileoInavDecoder::MakePegasusDtimeRows(
    const GalileoAuthenticatedTiming& data,
    PegasusDtimeRow* out_rows,
    int32_t max_rows)
{
    if (out_rows == nullptr || max_rows <= 0 || data.prn <= 0)
        return 0;

    const auto gps_week = [](int32_t gst_week) -> int32_t
    {
        return gst_week + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    };

    int32_t count = 0;

    if (data.utc_valid && count < max_rows)
    {
        PegasusDtimeRow& out = out_rows[count++];
        out = PegasusDtimeRow{};

        out.rx_week = gps_week(data.wt6_page_time.wn);
        out.rx_tom = data.wt6_page_time.tow;
        out.prn = data.prn;

        out.auth_status = AuthState::Yes;
        out.auth_reason = AuthReason::None;
        out.auth_week = gps_week(data.authentication_time.wn);
        out.auth_tom = data.authentication_time.tow;
        out.auth_adkd = data.authentication_adkd;
        out.auth_bits = data.auth_bits;
        out.nav_fingerprint = DtimeFingerprint(
            data.raw_wt6.data(), GAL_WT6, data.prn);

        out.target_time_system = PegasusTimeSystem::Utc;
        out.a0 = data.utc.a0;
        out.a1 = data.utc.a1;
        out.a2.reset();
        out.reference_week = gps_week(data.utc.WN0_UTC);
        out.reference_tom = static_cast<double>(data.utc.T0_UTC);
        out.tx_week = gps_week(data.wt6_page_time.wn);
        out.tx_tom = data.wt6_page_time.tow;
    }

    if (data.ggto_valid && count < max_rows)
    {
        PegasusDtimeRow& out = out_rows[count++];
        out = PegasusDtimeRow{};

        out.rx_week = gps_week(data.wt10_page_time.wn);
        out.rx_tom = data.wt10_page_time.tow;
        out.prn = data.prn;

        out.auth_status = AuthState::Yes;
        out.auth_reason = AuthReason::None;
        out.auth_week = gps_week(data.authentication_time.wn);
        out.auth_tom = data.authentication_time.tow;
        out.auth_adkd = data.authentication_adkd;
        out.auth_bits = data.auth_bits;
        out.nav_fingerprint = DtimeFingerprint(
            data.raw_wt10.data(), GAL_WT10, data.prn);

        out.target_time_system = PegasusTimeSystem::Gps;
        out.a0 = data.a0g;
        out.a1 = data.a1g;
        out.a2.reset();
        out.reference_week = gps_week(data.wn0g);
        out.reference_tom = static_cast<double>(data.t0g);
        out.tx_week = gps_week(data.wt10_page_time.wn);
        out.tx_tom = data.wt10_page_time.tow;
    }

    return count;
}

bool GalileoInavDecoder::MakeReceivedPegasusEphRow(
    const GalileoNavCandidate& candidate,
    NavSignalSource source,
    int32_t raw_source,
    PegasusEphRow& out)
{
    if (!candidate.HasCedData() || !candidate.has_ced_complete_time)
        return false;

    GalileoAuthenticatedCedStatus decoded{};
    const GnssTime no_auth_time{};

    if (!DecodeCedStatus(candidate,
        candidate.ced_complete_time,
        no_auth_time,
        0,
        0,
        source,
        raw_source,
        decoded))
    {
        return false;
    }

    if (!MakePegasusEphRow(decoded, out))
        return false;

    out.auth_status = AuthState::Unknown;
    out.auth_reason = AuthReason::WaitingForAuthentication;
    out.auth_week = PEGASUS_INVALID_WEEK;
    out.auth_tom = PEGASUS_INVALID_TOM;
    out.auth_adkd.reset();
    out.auth_bits = 0;
    return true;
}

bool GalileoInavDecoder::MakeReceivedPegasusIonoRow(
    const GalileoNavCandidate& candidate,
    PegasusIonoRow& out)
{
    out = PegasusIonoRow{};

    if (!candidate.HasWord(GAL_WT5) || candidate.prn <= 0)
        return false;

    const GalileoNavWord& word = candidate.words[GAL_WT5];
    if (!word.has_epoch || !IsTimeValid(word.page_epoch))
        return false;

    const std::uint8_t* wt5 = word.even.data();
    out.rx_week = word.page_epoch.wn + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    out.rx_tom = word.page_epoch.tow;
    out.prn = candidate.prn;
    out.auth_status = AuthState::Unknown;
    out.auth_reason = AuthReason::WaitingForAuthentication;
    out.auth_adkd.reset();
    out.auth_bits = 0;
    out.nav_fingerprint = IonoFingerprint(wt5, candidate.prn);
    out.ai0 = ScaleUnsigned(wt5, 6, 11, -2);
    out.ai1 = ScaleSigned(wt5, 17, 11, -8);
    out.ai2 = ScaleSigned(wt5, 28, 14, -15);

    std::uint8_t storm_flags = 0;
    for (int32_t i = 0; i < 5; ++i)
    {
        if (GetBitMsb0(wt5, 42 + i))
            storm_flags = static_cast<std::uint8_t>(storm_flags | (1u << i));
    }
    out.storm_flags = storm_flags;
    out.tx_week = out.rx_week;
    out.tx_tom = out.rx_tom;
    return true;
}

bool GalileoInavDecoder::MakeReceivedPegasusDtimeRow(
    const GalileoNavCandidate& candidate,
    int32_t wt,
    PegasusDtimeRow& out)
{
    out = PegasusDtimeRow{};

    if ((wt != GAL_WT6 && wt != GAL_WT10) ||
        !candidate.HasWord(wt) || candidate.prn <= 0)
    {
        return false;
    }

    const GalileoNavWord& word = candidate.words[wt];
    if (!word.has_epoch || !IsTimeValid(word.page_epoch))
        return false;

    const std::uint8_t* raw = word.even.data();
    out.rx_week = word.page_epoch.wn + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    out.rx_tom = word.page_epoch.tow;
    out.prn = candidate.prn;
    out.auth_status = AuthState::Unknown;
    out.auth_reason = AuthReason::WaitingForAuthentication;
    out.auth_adkd.reset();
    out.auth_bits = 0;
    out.nav_fingerprint = DtimeFingerprint(raw, wt, candidate.prn);
    out.a2.reset();
    out.tx_week = out.rx_week;
    out.tx_tom = out.rx_tom;

    if (wt == GAL_WT6)
    {
        out.target_time_system = PegasusTimeSystem::Utc;
        out.a0 = ScaleSigned(raw, 6, 32, -30);
        out.a1 = ScaleSigned(raw, 38, 24, -50);
        out.reference_tom = static_cast<double>(
            GetUnsignedBits64Msb0(raw, 70, 8) * 3600u);
        const int32_t gst_week = ResolveTruncatedWeek(
            word.page_epoch.wn,
            static_cast<int32_t>(GetUnsignedBits64Msb0(raw, 78, 8)),
            8);
        out.reference_week = gst_week + GALILEO_GST_TO_GPS_WEEK_OFFSET;
        return true;
    }

    const std::uint64_t raw_a0g = GetUnsignedBits64Msb0(raw, 86, 16);
    const std::uint64_t raw_a1g = GetUnsignedBits64Msb0(raw, 102, 12);
    const std::uint64_t raw_t0g = GetUnsignedBits64Msb0(raw, 114, 8);
    const std::uint64_t raw_wn0g = GetUnsignedBits64Msb0(raw, 122, 6);

    if (IsAllOnes(raw_a0g, 16) && IsAllOnes(raw_a1g, 12) &&
        IsAllOnes(raw_t0g, 8) && IsAllOnes(raw_wn0g, 6))
    {
        return false;
    }

    out.target_time_system = PegasusTimeSystem::Gps;
    out.a0 = ScaleSigned(raw, 86, 16, -35);
    out.a1 = ScaleSigned(raw, 102, 12, -51);
    out.reference_tom = static_cast<double>(raw_t0g * 3600u);
    const int32_t gst_week = ResolveTruncatedWeek(
        word.page_epoch.wn,
        static_cast<int32_t>(raw_wn0g),
        6);
    out.reference_week = gst_week + GALILEO_GST_TO_GPS_WEEK_OFFSET;
    return true;
}

void GalileoAuthDataFifo::Reset()
{
    ced_status_.clear();
    timing_.clear();
    pegasus_eph_rows_.clear();
    pegasus_iono_rows_.clear();
    pegasus_dtime_rows_.clear();
    pegasus_log_rows_.clear();
    last_rx_eph_.fill(std::nullopt);
    last_rx_iono_.fill(std::nullopt);
    last_auth_eph_.fill(std::nullopt);
    last_auth_iono_.fill(std::nullopt);
    for (auto& row : last_rx_dtime_) row.fill(std::nullopt);
    for (auto& row : last_auth_dtime_) row.fill(std::nullopt);
    eph_.clear();
    iono_.clear();
    time_.clear();
}

void GalileoAuthDataFifo::PushCedStatus(
    const GalileoAuthenticatedCedStatus& data)
{
    ced_status_.push_back(data);

    if (!ValidPegasusPrn(data.prn))
        return;

    const std::size_t prn = static_cast<std::size_t>(data.prn);

    PegasusEphRow eph_row{};
    if (GalileoInavDecoder::MakePegasusEphRow(data, eph_row) &&
        (!last_auth_eph_[prn].has_value() ||
         *last_auth_eph_[prn] != eph_row.nav_fingerprint))
    {
        pegasus_eph_rows_.push_back(eph_row);
        last_auth_eph_[prn] = eph_row.nav_fingerprint;
    }

    PegasusIonoRow iono_row{};
    if (GalileoInavDecoder::MakePegasusIonoRow(data, iono_row) &&
        (!last_auth_iono_[prn].has_value() ||
         *last_auth_iono_[prn] != iono_row.nav_fingerprint))
    {
        pegasus_iono_rows_.push_back(iono_row);
        last_auth_iono_[prn] = iono_row.nav_fingerprint;
    }
}

void GalileoAuthDataFifo::PushTiming(
    const GalileoAuthenticatedTiming& data)
{
    timing_.push_back(data);

    if (!ValidPegasusPrn(data.prn))
        return;

    const std::size_t prn = static_cast<std::size_t>(data.prn);
    std::array<PegasusDtimeRow, 2> rows{};
    const int32_t row_count =
        GalileoInavDecoder::MakePegasusDtimeRows(
            data,
            rows.data(),
            static_cast<int32_t>(rows.size()));

    for (int32_t i = 0; i < row_count; ++i)
    {
        const PegasusDtimeRow& row = rows[static_cast<std::size_t>(i)];
        const std::size_t target =
            row.target_time_system == PegasusTimeSystem::Utc ? 0u : 1u;

        if (!last_auth_dtime_[prn][target].has_value() ||
            *last_auth_dtime_[prn][target] != row.nav_fingerprint)
        {
            pegasus_dtime_rows_.push_back(row);
            last_auth_dtime_[prn][target] = row.nav_fingerprint;
        }
    }
}

void GalileoAuthDataFifo::ObserveNavigation(
    const GalileoNavFeedObservation& observation,
    NavSignalSource source,
    int32_t raw_source)
{
    if (!observation.valid || !observation.content_changed ||
        !ValidPegasusPrn(observation.candidate.prn))
    {
        return;
    }

    const int32_t prn_value = observation.candidate.prn;
    const std::size_t prn = static_cast<std::size_t>(prn_value);

    if (observation.wt >= GAL_WT1 && observation.wt <= GAL_WT5)
    {
        PegasusEphRow eph{};
        if (GalileoInavDecoder::MakeReceivedPegasusEphRow(
            observation.candidate, source, raw_source, eph) &&
            (!last_rx_eph_[prn].has_value() ||
             *last_rx_eph_[prn] != eph.nav_fingerprint))
        {
            pegasus_eph_rows_.push_back(eph);
            last_rx_eph_[prn] = eph.nav_fingerprint;
        }

        if (observation.wt == GAL_WT5)
        {
            PegasusIonoRow iono{};
            if (GalileoInavDecoder::MakeReceivedPegasusIonoRow(
                observation.candidate, iono) &&
                (!last_rx_iono_[prn].has_value() ||
                 *last_rx_iono_[prn] != iono.nav_fingerprint))
            {
                pegasus_iono_rows_.push_back(iono);
                last_rx_iono_[prn] = iono.nav_fingerprint;
            }
        }
        return;
    }

    if (observation.wt == GAL_WT6 || observation.wt == GAL_WT10)
    {
        PegasusDtimeRow dtime{};
        if (!GalileoInavDecoder::MakeReceivedPegasusDtimeRow(
            observation.candidate, observation.wt, dtime))
        {
            return;
        }

        const std::size_t target = observation.wt == GAL_WT6 ? 0u : 1u;
        if (!last_rx_dtime_[prn][target].has_value() ||
            *last_rx_dtime_[prn][target] != dtime.nav_fingerprint)
        {
            pegasus_dtime_rows_.push_back(dtime);
            last_rx_dtime_[prn][target] = dtime.nav_fingerprint;
        }
    }
}

void GalileoAuthDataFifo::PushLog(const PegasusLogRow& row)
{
    pegasus_log_rows_.push_back(row);
}

bool GalileoAuthDataFifo::PopCedStatus(
    GalileoAuthenticatedCedStatus& data)
{
    if (ced_status_.empty())
        return false;

    data = ced_status_.front();
    ced_status_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopTiming(
    GalileoAuthenticatedTiming& data)
{
    if (timing_.empty())
        return false;

    data = timing_.front();
    timing_.pop_front();
    return true;
}

int32_t GalileoAuthDataFifo::CedStatusCount() const
{
    return static_cast<int32_t>(ced_status_.size());
}

int32_t GalileoAuthDataFifo::TimingCount() const
{
    return static_cast<int32_t>(timing_.size());
}


bool GalileoAuthDataFifo::PopPegasusEphRow(PegasusEphRow& row)
{
    if (pegasus_eph_rows_.empty())
        return false;

    row = pegasus_eph_rows_.front();
    pegasus_eph_rows_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopPegasusIonoRow(PegasusIonoRow& row)
{
    if (pegasus_iono_rows_.empty())
        return false;

    row = pegasus_iono_rows_.front();
    pegasus_iono_rows_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopPegasusDtimeRow(PegasusDtimeRow& row)
{
    if (pegasus_dtime_rows_.empty())
        return false;

    row = pegasus_dtime_rows_.front();
    pegasus_dtime_rows_.pop_front();
    return true;
}

int32_t GalileoAuthDataFifo::PegasusEphRowCount() const
{
    return static_cast<int32_t>(pegasus_eph_rows_.size());
}

int32_t GalileoAuthDataFifo::PegasusIonoRowCount() const
{
    return static_cast<int32_t>(pegasus_iono_rows_.size());
}

int32_t GalileoAuthDataFifo::PegasusDtimeRowCount() const
{
    return static_cast<int32_t>(pegasus_dtime_rows_.size());
}

bool GalileoAuthDataFifo::PopPegasusLogRow(PegasusLogRow& row)
{
    if (pegasus_log_rows_.empty())
        return false;

    row = pegasus_log_rows_.front();
    pegasus_log_rows_.pop_front();
    return true;
}

int32_t GalileoAuthDataFifo::PegasusLogRowCount() const
{
    return static_cast<int32_t>(pegasus_log_rows_.size());
}

void GalileoAuthDataFifo::PushEph(const GALEphDecodedType& eph)
{
    AuthEphRecord r;
    r.data = eph;
    eph_.push_back(r);
}

void GalileoAuthDataFifo::PushIono(const GALIonoDecodedType& iono)
{
    AuthIonoRecord r;
    r.data = iono;
    iono_.push_back(r);
}

void GalileoAuthDataFifo::PushTime(const GALTimeDecodedType& time)
{
    AuthTimeRecord r;
    r.data = time;
    time_.push_back(r);
}

bool GalileoAuthDataFifo::PopEph(GALEphDecodedType& eph)
{
    if (eph_.empty())
        return false;

    eph = eph_.front().data;
    eph_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopIono(GALIonoDecodedType& iono)
{
    if (iono_.empty())
        return false;

    iono = iono_.front().data;
    iono_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopTime(GALTimeDecodedType& time)
{
    if (time_.empty())
        return false;

    time = time_.front().data;
    time_.pop_front();
    return true;
}

int32_t GalileoAuthDataFifo::EphCount() const
{
    return static_cast<int32_t>(eph_.size());
}

int32_t GalileoAuthDataFifo::IonoCount() const
{
    return static_cast<int32_t>(iono_.size());
}

int32_t GalileoAuthDataFifo::TimeCount() const
{
    return static_cast<int32_t>(time_.size());
}
