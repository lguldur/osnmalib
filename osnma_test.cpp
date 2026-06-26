// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "osnma_authenticator.h"
#include "osnma_raw_json_reader.h"
#include "osnma_official_test_vector_reader.h"
#include "osnma_xml_material_loader.h"
#include "osnma_self_test.h"
#include "pegasus_csv_writer.h"

// -tv "D:\data\osnma\Test_vectors" > d:\data\osnma\out.txt
// -tv "D:\data\osnma\Test_vectors" configuration_1 16_AUG_2023_GST_05_00_01.csv > d:\data\osnma\out.txt
// -json D:\data\osnma\week_1397_1h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml > d:\data\osnma\jsonout.txt
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml > d:\data\osnma\jsonout.txt
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml --print-nav > d:\data\osnma\jsonout_nav.txt
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml --rinex-prefix D:\data\osnma\week_1397
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml --rinex4-prefix D:\data\osnma\week_1397
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml --pegasus-prefix D:\data\osnma\week_1397

namespace
{
    constexpr int32_t GALILEO_WEEK_TO_CONTINUOUS_GPS_WEEK = 1024;
    constexpr double SECONDS_PER_WEEK = 604800.0;
    constexpr double RINEX_UNKNOWN_TRANSMISSION_TIME = 999999999.999;

    struct CalendarFields
    {
        int32_t year = 0;
        int32_t month = 0;
        int32_t day = 0;
        int32_t hour = 0;
        int32_t minute = 0;
        int32_t second = 0;
    };

    struct AuthenticatedNavigationRecords
    {
        std::vector<GalileoAuthenticatedCedStatus> ced_status;
        std::vector<GalileoAuthenticatedTiming> timing;
    };

    struct Rinex4WriteCounts
    {
        int32_t ephemeris = 0;
        int32_t ionosphere = 0;
        int32_t utc_offset = 0;
        int32_t ggto_offset = 0;
    };

    enum class Rinex4RecordKind : int32_t
    {
        Ephemeris = 0,
        Ionosphere = 1,
        UtcOffset = 2,
        GgtoOffset = 3
    };

    struct Rinex4Event
    {
        double absolute_gst_seconds = 0.0;
        int32_t prn = 0;
        Rinex4RecordKind kind = Rinex4RecordKind::Ephemeris;
        std::size_t record_index = 0;
    };

    int32_t GstWeekToRinexWeek(int32_t gst_week)
    {
        return gst_week + GALILEO_WEEK_TO_CONTINUOUS_GPS_WEEK;
    }

    bool GstToCalendar(int32_t gst_week,
        double tow,
        CalendarFields& out)
    {
        if (gst_week < 0 || !std::isfinite(tow))
            return false;

        using namespace std::chrono;

        const int64_t rinex_week =
            static_cast<int64_t>(GstWeekToRinexWeek(gst_week));

        const int64_t seconds_from_gps_epoch =
            rinex_week * 604800LL +
            static_cast<int64_t>(std::llround(tow));

        const sys_seconds gps_epoch =
            sys_days{year{1980} / January / day{6}};

        const sys_seconds time =
            gps_epoch + seconds{seconds_from_gps_epoch};

        const sys_days date = floor<days>(time);
        const year_month_day ymd{date};
        const hh_mm_ss<seconds> tod{time - date};

        if (!ymd.ok())
            return false;

        out.year = static_cast<int32_t>(ymd.year());
        out.month = static_cast<int32_t>(
            static_cast<unsigned>(ymd.month()));
        out.day = static_cast<int32_t>(
            static_cast<unsigned>(ymd.day()));
        out.hour = static_cast<int32_t>(tod.hours().count());
        out.minute = static_cast<int32_t>(tod.minutes().count());
        out.second = static_cast<int32_t>(tod.seconds().count());
        return true;
    }

    std::string RinexDouble(double value,
        int32_t width = 19,
        int32_t precision = 12)
    {
        char format[32]{};
        char buffer[96]{};

        std::snprintf(format,
            sizeof(format),
            "%%%d.%dE",
            width,
            precision);

        std::snprintf(buffer,
            sizeof(buffer),
            format,
            value);

        for (char* p = buffer; *p != '\0'; ++p)
        {
            if (*p == 'E')
                *p = 'D';
        }

        return std::string(buffer);
    }

    std::string Rinex4Double(double value,
        int32_t width = 19,
        int32_t precision = 12)
    {
        char format[32]{};
        char buffer[96]{};

        std::snprintf(format,
            sizeof(format),
            "%%%d.%dE",
            width,
            precision);

        std::snprintf(buffer,
            sizeof(buffer),
            format,
            value);

        return std::string(buffer);
    }

    void WriteRinex4Values(std::FILE* out,
        const double* values,
        std::size_t value_count)
    {
        if (out == nullptr || values == nullptr || value_count == 0)
            return;

        std::fputs("    ", out);
        for (std::size_t i = 0; i < value_count; ++i)
        {
            const std::string field = Rinex4Double(values[i]);
            std::fputs(field.c_str(), out);
        }
        std::fputc('\n', out);
    }

    void WriteRinexFour(std::FILE* out,
        double a,
        double b,
        double c,
        double d)
    {
        if (out == nullptr)
            return;

        const std::string fa = RinexDouble(a);
        const std::string fb = RinexDouble(b);
        const std::string fc = RinexDouble(c);
        const std::string fd = RinexDouble(d);

        std::fprintf(out, "    %s%s%s%s\n",
            fa.c_str(),
            fb.c_str(),
            fc.c_str(),
            fd.c_str());
    }

    double SisaIndexToMeters(std::uint8_t index)
    {
        if (index <= 49u)
            return static_cast<double>(index) * 0.01;

        if (index <= 74u)
            return 0.50 + static_cast<double>(index - 50u) * 0.02;

        if (index <= 99u)
            return 1.00 + static_cast<double>(index - 75u) * 0.04;

        if (index <= 125u)
            return 2.00 + static_cast<double>(index - 100u) * 0.16;

        // RINEX uses -1 when no usable accuracy prediction is available.
        return -1.0;
    }

    GnssTime PreferredPageEpoch(
        const GnssTime& page_epoch,
        const GnssTime& navigation_time);

    double RinexTransmissionTime(
        const GalileoAuthenticatedCedStatus& data)
    {
        const GnssTime transmission_time =
            PreferredPageEpoch(data.ephemeris_transmission_time,
                data.navigation_time);

        if (!IsTimeValid(transmission_time) ||
            data.ephemeris.WNToe > static_cast<unsigned long>(INT32_MAX))
        {
            return RINEX_UNKNOWN_TRANSMISSION_TIME;
        }

        const int32_t toe_gst_week =
            static_cast<int32_t>(data.ephemeris.WNToe);

        return transmission_time.tow +
            static_cast<double>(transmission_time.wn - toe_gst_week) *
            SECONDS_PER_WEEK;
    }

    void WriteHeaderStyleLine(std::FILE* out,
        const std::string& content,
        const char* label)
    {
        if (out == nullptr)
            return;

        std::fprintf(out, "%-60.60s%-20.20s\n",
            content.c_str(),
            label != nullptr ? label : "");
    }

    bool WriteAuthenticatedCedAsRinex(
        std::FILE* out,
        const GalileoAuthenticatedCedStatus& data,
        bool include_diagnostics,
        bool include_ionosphere_record)
    {
        if (out == nullptr)
            return false;

        const GALEphDecodedType& eph = data.ephemeris;

        if (include_diagnostics)
        {
            std::fprintf(out,
                "# OSNMA E%02d NAV_GST=%d/%.0f AUTH_GST=%d/%.0f "
                "ADKD=%d AUTHBITS=%lld IODNAV=%d SISA_INDEX=%u\n",
                data.prn,
                data.navigation_time.wn,
                data.navigation_time.tow,
                data.authentication_time.wn,
                data.authentication_time.tow,
                static_cast<int32_t>(data.authentication_adkd),
                static_cast<long long>(data.auth_bits),
                data.iodnav,
                static_cast<unsigned>(data.sisa));
        }

        if (!data.ephemeris_valid)
        {
            if (include_diagnostics)
            {
                std::fprintf(out,
                    "# RINEX record skipped: ephemeris_valid=0 "
                    "iodnav_consistent=%d svid_matches_prn=%d\n",
                    data.iodnav_consistent ? 1 : 0,
                    data.svid_matches_prn ? 1 : 0);
            }
            return false;
        }

        CalendarFields epoch{};

        if (!GstToCalendar(
            static_cast<int32_t>(eph.WNToc),
            static_cast<double>(eph.Toc),
            epoch))
        {
            if (include_diagnostics)
                std::fprintf(out, "# RINEX record skipped: invalid Toc epoch\n");
            return false;
        }

        const std::string af0 = RinexDouble(eph.af0);
        const std::string af1 = RinexDouble(eph.af1);
        const std::string af2 = RinexDouble(eph.af2);

        std::fprintf(out,
            "E%02d %04d %02d %02d %02d %02d %02d%s%s%s\n",
            data.prn,
            epoch.year,
            epoch.month,
            epoch.day,
            epoch.hour,
            epoch.minute,
            epoch.second,
            af0.c_str(),
            af1.c_str(),
            af2.c_str());

        WriteRinexFour(out,
            static_cast<double>(eph.IODNav),
            eph.Crs,
            eph.DeltaN,
            eph.M0);

        WriteRinexFour(out,
            eph.Cuc,
            eph.Ecc,
            eph.Cus,
            eph.sqrtA);

        WriteRinexFour(out,
            static_cast<double>(eph.Toe),
            eph.Cic,
            eph.Omega0,
            eph.Cis);

        WriteRinexFour(out,
            eph.i0,
            eph.Crc,
            eph.Omega,
            eph.OmegaDot);

        WriteRinexFour(out,
            eph.IDot,
            static_cast<double>(eph.DataSources),
            static_cast<double>(GstWeekToRinexWeek(
                static_cast<int32_t>(eph.WNToe))),
            0.0);

        WriteRinexFour(out,
            SisaIndexToMeters(data.sisa),
            static_cast<double>(eph.SVHealth),
            eph.BGD_L1E5a,
            eph.BGD_L1E5b);

        WriteRinexFour(out,
            RinexTransmissionTime(data),
            0.0,
            0.0,
            0.0);

        if (include_ionosphere_record && data.ionosphere_valid)
        {
            char content[128]{};
            const std::string ai0 = RinexDouble(data.ionosphere.ai0, 12, 4);
            const std::string ai1 = RinexDouble(data.ionosphere.ai1, 12, 4);
            const std::string ai2 = RinexDouble(data.ionosphere.ai2, 12, 4);
            const std::string zero = RinexDouble(0.0, 12, 4);

            std::snprintf(content,
                sizeof(content),
                "GAL %s%s%s%s",
                ai0.c_str(),
                ai1.c_str(),
                ai2.c_str(),
                zero.c_str());

            WriteHeaderStyleLine(out, content, "IONOSPHERIC CORR");

            if (include_diagnostics)
            {
                std::fprintf(out,
                    "# IONO E%02d storm_flags=0x%02X\n",
                    data.prn,
                    static_cast<unsigned>(data.ionosphere.StormFlags));
            }
        }

        return true;
    }

    double AbsoluteGstSeconds(const GnssTime& time)
    {
        if (!IsTimeValid(time))
            return 0.0;

        return static_cast<double>(time.wn) * SECONDS_PER_WEEK + time.tow;
    }

    GnssTime PreferredPageEpoch(
        const GnssTime& page_epoch,
        const GnssTime& navigation_time)
    {
        if (!IsTimeValid(page_epoch))
            return navigation_time;

        if (!IsTimeValid(navigation_time))
            return page_epoch;

        // A default-constructed GnssTime is {0,0} and passes IsTimeValid().
        // Reject such a placeholder when it is clearly unrelated to the
        // authenticated navigation epoch.
        if (std::fabs(DiffSeconds(page_epoch, navigation_time)) > 86400.0)
            return navigation_time;

        return page_epoch;
    }

    double TransmissionTimeRelativeToWeek(
        const GnssTime& transmission_time,
        int32_t reference_gst_week)
    {
        if (!IsTimeValid(transmission_time) || reference_gst_week < 0)
            return RINEX_UNKNOWN_TRANSMISSION_TIME;

        return transmission_time.tow +
            static_cast<double>(transmission_time.wn - reference_gst_week) *
            SECONDS_PER_WEEK;
    }

    bool SameIonosphereModel(
        const GALIonoDecodedType& a,
        const GALIonoDecodedType& b)
    {
        return a.ai0 == b.ai0 &&
            a.ai1 == b.ai1 &&
            a.ai2 == b.ai2 &&
            a.StormFlags == b.StormFlags;
    }

    bool SameUtcOffset(
        const GalileoAuthenticatedTiming& a,
        const GalileoAuthenticatedTiming& b)
    {
        return a.utc.a0 == b.utc.a0 &&
            a.utc.a1 == b.utc.a1 &&
            a.utc.T0_UTC == b.utc.T0_UTC &&
            a.utc.WN0_UTC == b.utc.WN0_UTC;
    }

    bool SameGgtoOffset(
        const GalileoAuthenticatedTiming& a,
        const GalileoAuthenticatedTiming& b)
    {
        return a.a0g == b.a0g &&
            a.a1g == b.a1g &&
            a.t0g == b.t0g &&
            a.wn0g == b.wn0g;
    }

    bool WriteAuthenticatedCedAsRinex4Ephemeris(
        std::FILE* out,
        const GalileoAuthenticatedCedStatus& data)
    {
        if (out == nullptr || !data.ephemeris_valid)
            return false;

        const GALEphDecodedType& eph = data.ephemeris;
        CalendarFields epoch{};

        if (!GstToCalendar(
            static_cast<int32_t>(eph.WNToc),
            static_cast<double>(eph.Toc),
            epoch))
        {
            return false;
        }

        std::fprintf(out, "> EPH E%02d INAV\n", data.prn);

        const std::string af0 = Rinex4Double(eph.af0);
        const std::string af1 = Rinex4Double(eph.af1);
        const std::string af2 = Rinex4Double(eph.af2);

        std::fprintf(out,
            "E%02d %04d %02d %02d %02d %02d %02d%s%s%s\n",
            data.prn,
            epoch.year,
            epoch.month,
            epoch.day,
            epoch.hour,
            epoch.minute,
            epoch.second,
            af0.c_str(),
            af1.c_str(),
            af2.c_str());

        const double orbit_1[] = {
            static_cast<double>(eph.IODNav),
            eph.Crs,
            eph.DeltaN,
            eph.M0
        };
        WriteRinex4Values(out, orbit_1, 4);

        const double orbit_2[] = {
            eph.Cuc,
            eph.Ecc,
            eph.Cus,
            eph.sqrtA
        };
        WriteRinex4Values(out, orbit_2, 4);

        const double orbit_3[] = {
            static_cast<double>(eph.Toe),
            eph.Cic,
            eph.Omega0,
            eph.Cis
        };
        WriteRinex4Values(out, orbit_3, 4);

        const double orbit_4[] = {
            eph.i0,
            eph.Crc,
            eph.Omega,
            eph.OmegaDot
        };
        WriteRinex4Values(out, orbit_4, 4);

        const double orbit_5[] = {
            eph.IDot,
            static_cast<double>(eph.DataSources),
            static_cast<double>(GstWeekToRinexWeek(
                static_cast<int32_t>(eph.WNToe)))
        };
        WriteRinex4Values(out, orbit_5, 3);

        const double orbit_6[] = {
            SisaIndexToMeters(data.sisa),
            static_cast<double>(eph.SVHealth),
            eph.BGD_L1E5a,
            eph.BGD_L1E5b
        };
        WriteRinex4Values(out, orbit_6, 4);

        const double orbit_7[] = {
            RinexTransmissionTime(data)
        };
        WriteRinex4Values(out, orbit_7, 1);

        return true;
    }

    bool WriteAuthenticatedCedAsRinex4Ionosphere(
        std::FILE* out,
        const GalileoAuthenticatedCedStatus& data)
    {
        if (out == nullptr || !data.ionosphere_valid)
            return false;

        const GnssTime transmission_time =
            PreferredPageEpoch(data.wt5_page_time, data.navigation_time);

        if (!IsTimeValid(transmission_time))
            return false;

        CalendarFields epoch{};
        if (!GstToCalendar(
            transmission_time.wn,
            transmission_time.tow,
            epoch))
        {
            return false;
        }

        std::fprintf(out, "> ION E%02d IFNV\n", data.prn);

        const std::string ai0 = Rinex4Double(data.ionosphere.ai0);
        const std::string ai1 = Rinex4Double(data.ionosphere.ai1);
        const std::string ai2 = Rinex4Double(data.ionosphere.ai2);

        std::fprintf(out,
            "    %04d %02d %02d %02d %02d %02d%s%s%s\n",
            epoch.year,
            epoch.month,
            epoch.day,
            epoch.hour,
            epoch.minute,
            epoch.second,
            ai0.c_str(),
            ai1.c_str(),
            ai2.c_str());

        const double flags[] = {
            static_cast<double>(data.ionosphere.StormFlags)
        };
        WriteRinex4Values(out, flags, 1);
        return true;
    }

    bool WriteAuthenticatedTimingAsRinex4UtcOffset(
        std::FILE* out,
        const GalileoAuthenticatedTiming& data)
    {
        if (out == nullptr || !data.utc_valid)
            return false;

        CalendarFields epoch{};
        if (!GstToCalendar(
            data.utc.WN0_UTC,
            static_cast<double>(data.utc.T0_UTC),
            epoch))
        {
            return false;
        }

        std::fprintf(out, "> STO E%02d IFNV\n", data.prn);
        std::fprintf(out,
            "    %04d %02d %02d %02d %02d %02d %-18.18s %-18.18s %-18.18s\n",
            epoch.year,
            epoch.month,
            epoch.day,
            epoch.hour,
            epoch.minute,
            epoch.second,
            "GAUT",
            "",
            "UTCGAL");

        const double values[] = {
            TransmissionTimeRelativeToWeek(
                PreferredPageEpoch(
                    data.wt6_page_time,
                    data.navigation_time),
                data.utc.WN0_UTC),
            data.utc.a0,
            data.utc.a1,
            0.0
        };
        WriteRinex4Values(out, values, 4);
        return true;
    }

    bool WriteAuthenticatedTimingAsRinex4GgtoOffset(
        std::FILE* out,
        const GalileoAuthenticatedTiming& data)
    {
        if (out == nullptr || !data.ggto_valid)
            return false;

        CalendarFields epoch{};
        if (!GstToCalendar(
            data.wn0g,
            static_cast<double>(data.t0g),
            epoch))
        {
            return false;
        }

        std::fprintf(out, "> STO E%02d IFNV\n", data.prn);
        std::fprintf(out,
            "    %04d %02d %02d %02d %02d %02d %-18.18s %-18.18s %-18.18s\n",
            epoch.year,
            epoch.month,
            epoch.day,
            epoch.hour,
            epoch.minute,
            epoch.second,
            "GAGP",
            "",
            "");

        const double values[] = {
            TransmissionTimeRelativeToWeek(
                PreferredPageEpoch(
                    data.wt10_page_time,
                    data.navigation_time),
                data.wn0g),
            data.a0g,
            data.a1g,
            0.0
        };
        WriteRinex4Values(out, values, 4);
        return true;
    }

    void WriteAuthenticatedTimingAsRinexHeader(
        std::FILE* out,
        const GalileoAuthenticatedTiming& data,
        bool include_diagnostics)
    {
        if (out == nullptr)
            return;

        if (include_diagnostics)
        {
            std::fprintf(out,
                "# OSNMA-TIME E%02d NAV_GST=%d/%.0f AUTH_GST=%d/%.0f "
                "AUTHBITS=%lld\n",
                data.prn,
                data.navigation_time.wn,
                data.navigation_time.tow,
                data.authentication_time.wn,
                data.authentication_time.tow,
                static_cast<long long>(data.auth_bits));
        }

        if (data.utc_valid)
        {
            char content[160]{};
            const std::string a0 = RinexDouble(data.utc.a0, 17, 10);
            const std::string a1 = RinexDouble(data.utc.a1, 16, 9);

            std::snprintf(content,
                sizeof(content),
                "GAUT %s%s %6d %4d E%02d  0",
                a0.c_str(),
                a1.c_str(),
                data.utc.T0_UTC,
                GstWeekToRinexWeek(data.utc.WN0_UTC),
                data.prn);

            WriteHeaderStyleLine(out, content, "TIME SYSTEM CORR");

            if (include_diagnostics)
            {
                std::fprintf(out,
                    "# LEAP E%02d current=%d future=%d WN_LSF_GST=%d "
                    "WN_LSF_RINEX=%d DN=%d\n",
                    data.prn,
                    data.utc.DeltaT_LS,
                    data.utc.DeltaT_LSF,
                    data.utc.WN_LSF,
                    GstWeekToRinexWeek(data.utc.WN_LSF),
                    data.utc.DN_LSF);
            }
        }

        if (data.ggto_valid)
        {
            char content[160]{};
            const std::string a0 = RinexDouble(data.a0g, 17, 10);
            const std::string a1 = RinexDouble(data.a1g, 16, 9);

            std::snprintf(content,
                sizeof(content),
                "GAGP %s%s %6d %4d E%02d  0",
                a0.c_str(),
                a1.c_str(),
                data.t0g,
                GstWeekToRinexWeek(data.wn0g),
                data.prn);

            WriteHeaderStyleLine(out, content, "TIME SYSTEM CORR");
        }
    }

    AuthenticatedNavigationRecords CollectAuthenticatedNavigation(
        OsnmaAuthenticator& auth)
    {
        AuthenticatedNavigationRecords records{};

        records.ced_status.reserve(
            static_cast<std::size_t>(auth.AuthenticatedCedStatusCount()));
        records.timing.reserve(
            static_cast<std::size_t>(auth.AuthenticatedTimingCount()));

        GalileoAuthenticatedCedStatus ced{};
        while (auth.PopAuthenticatedCedStatus(ced))
            records.ced_status.push_back(ced);

        GalileoAuthenticatedTiming timing{};
        while (auth.PopAuthenticatedTiming(timing))
            records.timing.push_back(timing);

        return records;
    }

    void PrintAuthenticatedNavigationDump(
        const AuthenticatedNavigationRecords& records)
    {
        std::printf(
            "\n===== BEGIN AUTHENTICATED GALILEO RINEX 3.05 COMPARISON DUMP =====\n");
        std::printf("# CED/status records queued: %d\n",
            static_cast<int32_t>(records.ced_status.size()));
        std::printf("# Timing records queued: %d\n",
            static_cast<int32_t>(records.timing.size()));
        std::printf("# Galileo week values in the RINEX records are GST week + 1024.\n");
        std::printf("# Data source 513 means I/NAV E1-B plus E5b/E1 clock parameters.\n");
        std::printf("# Lines beginning with # are diagnostics, not RINEX records.\n");

        int32_t ced_printed = 0;
        int32_t ced_skipped = 0;

        for (const GalileoAuthenticatedCedStatus& ced : records.ced_status)
        {
            if (WriteAuthenticatedCedAsRinex(
                stdout,
                ced,
                true,
                true))
            {
                ++ced_printed;
            }
            else
            {
                ++ced_skipped;
            }
        }

        std::printf("\n# AUTHENTICATED UTC/GGTO HEADER-STYLE RECORDS\n");

        for (const GalileoAuthenticatedTiming& timing : records.timing)
        {
            WriteAuthenticatedTimingAsRinexHeader(
                stdout,
                timing,
                true);
        }

        std::printf(
            "# Dump summary: ced_printed=%d ced_skipped=%d timing_printed=%d\n",
            ced_printed,
            ced_skipped,
            static_cast<int32_t>(records.timing.size()));
        std::printf(
            "===== END AUTHENTICATED GALILEO RINEX 3.05 COMPARISON DUMP =====\n");
    }

    std::string CurrentUtcRinexDate()
    {
        const std::time_t now = std::time(nullptr);
        std::tm utc{};

#if defined(_WIN32)
        if (gmtime_s(&utc, &now) != 0)
            return "00000000 000000 UTC";
#else
        if (gmtime_r(&now, &utc) == nullptr)
            return "00000000 000000 UTC";
#endif

        char buffer[32]{};
        std::snprintf(buffer,
            sizeof(buffer),
            "%04d%02d%02d %02d%02d%02d UTC",
            utc.tm_year + 1900,
            utc.tm_mon + 1,
            utc.tm_mday,
            utc.tm_hour,
            utc.tm_min,
            utc.tm_sec);
        return std::string(buffer);
    }

    std::filesystem::path MakeRinexOutputFilename(
        const char* prefix)
    {
        const std::filesystem::path prefix_path(
            prefix != nullptr ? prefix : "");

        const std::string filename =
            prefix_path.filename().string() + "_osnma_nav.rnx";

        return prefix_path.parent_path() / filename;
    }

    std::FILE* OpenTextFileForWriting(
        const std::filesystem::path& filename)
    {
#if defined(_WIN32)
        std::FILE* file = nullptr;
        if (_wfopen_s(&file, filename.c_str(), L"w") != 0)
            return nullptr;
        return file;
#else
        return std::fopen(filename.string().c_str(), "w");
#endif
    }

    void WriteRinexFileHeader(
        std::FILE* out,
        const AuthenticatedNavigationRecords& records)
    {
        WriteHeaderStyleLine(out,
            "     3.05           N: GNSS NAV DATA    E: GALILEO",
            "RINEX VERSION / TYPE");

        char program_line[128]{};
        const std::string utc_date = CurrentUtcRinexDate();
        std::snprintf(program_line,
            sizeof(program_line),
            "%-20.20s%-20.20s%-20.20s",
            "OSNMALIB",
            "OSNMA",
            utc_date.c_str());
        WriteHeaderStyleLine(out, program_line, "PGM / RUN BY / DATE");

        WriteHeaderStyleLine(out,
            "GALILEO I/NAV EPHEMERIDES AUTHENTICATED BY OSNMA",
            "COMMENT");
        WriteHeaderStyleLine(out,
            "ONLY VALID AUTHENTICATED EPHEMERIS RECORDS ARE WRITTEN",
            "COMMENT");

        for (const GalileoAuthenticatedCedStatus& ced : records.ced_status)
        {
            if (!ced.ionosphere_valid)
                continue;

            char content[128]{};
            const std::string ai0 = RinexDouble(ced.ionosphere.ai0, 12, 4);
            const std::string ai1 = RinexDouble(ced.ionosphere.ai1, 12, 4);
            const std::string ai2 = RinexDouble(ced.ionosphere.ai2, 12, 4);
            const std::string zero = RinexDouble(0.0, 12, 4);

            std::snprintf(content,
                sizeof(content),
                "GAL %s%s%s%s",
                ai0.c_str(),
                ai1.c_str(),
                ai2.c_str(),
                zero.c_str());
            WriteHeaderStyleLine(out, content, "IONOSPHERIC CORR");
            break;
        }

        const GalileoAuthenticatedTiming* first_utc = nullptr;
        const GalileoAuthenticatedTiming* first_ggto = nullptr;

        for (const GalileoAuthenticatedTiming& timing : records.timing)
        {
            if (first_utc == nullptr && timing.utc_valid)
                first_utc = &timing;
            if (first_ggto == nullptr && timing.ggto_valid)
                first_ggto = &timing;
            if (first_utc != nullptr && first_ggto != nullptr)
                break;
        }

        if (first_utc != nullptr)
        {
            const GalileoAuthenticatedTiming& timing = *first_utc;
            char content[160]{};
            const std::string a0 = RinexDouble(timing.utc.a0, 17, 10);
            const std::string a1 = RinexDouble(timing.utc.a1, 16, 9);

            std::snprintf(content,
                sizeof(content),
                "GAUT %s%s %6d %4d E%02d  0",
                a0.c_str(),
                a1.c_str(),
                timing.utc.T0_UTC,
                GstWeekToRinexWeek(timing.utc.WN0_UTC),
                timing.prn);
            WriteHeaderStyleLine(out, content, "TIME SYSTEM CORR");

            /*
                Galileo broadcasts WN_LSF modulo 256. Resolving it to the
                nearest current week is wrong when it still refers to a past
                leap-second event. Until historical disambiguation is added,
                write only the unambiguous current leap-second value. The
                RINEX time-system identifier is deliberately left blank.
            */
            std::snprintf(content,
                sizeof(content),
                "%6d",
                timing.utc.DeltaT_LS);
            WriteHeaderStyleLine(out, content, "LEAP SECONDS");
        }

        if (first_ggto != nullptr)
        {
            const GalileoAuthenticatedTiming& timing = *first_ggto;
            char content[160]{};
            const std::string a0 = RinexDouble(timing.a0g, 17, 10);
            const std::string a1 = RinexDouble(timing.a1g, 16, 9);

            std::snprintf(content,
                sizeof(content),
                "GAGP %s%s %6d %4d E%02d  0",
                a0.c_str(),
                a1.c_str(),
                timing.t0g,
                GstWeekToRinexWeek(timing.wn0g),
                timing.prn);
            WriteHeaderStyleLine(out, content, "TIME SYSTEM CORR");
        }

        WriteHeaderStyleLine(out, "", "END OF HEADER");
    }

    bool WriteAuthenticatedNavigationRinexFile(
        const AuthenticatedNavigationRecords& records,
        const char* prefix,
        std::string& filename_written,
        int32_t& record_count)
    {
        filename_written.clear();
        record_count = 0;

        if (prefix == nullptr || prefix[0] == '\0')
            return false;

        const std::filesystem::path filename =
            MakeRinexOutputFilename(prefix);

        std::error_code ec{};
        const std::filesystem::path parent = filename.parent_path();
        if (!parent.empty())
            std::filesystem::create_directories(parent, ec);

        if (ec)
            return false;

        std::FILE* out = OpenTextFileForWriting(filename);
        if (out == nullptr)
            return false;

        WriteRinexFileHeader(out, records);

        for (const GalileoAuthenticatedCedStatus& ced : records.ced_status)
        {
            if (WriteAuthenticatedCedAsRinex(
                out,
                ced,
                false,
                false))
            {
                ++record_count;
            }
        }

        const bool close_ok = (std::fclose(out) == 0);
        if (!close_ok)
            return false;

        filename_written = filename.string();
        return true;
    }

    std::filesystem::path MakeRinex4OutputFilename(
        const char* prefix)
    {
        const std::filesystem::path prefix_path(
            prefix != nullptr ? prefix : "");

        const std::string filename =
            prefix_path.filename().string() + "_osnma_nav4.rnx";

        return prefix_path.parent_path() / filename;
    }

    void WriteRinex4FileHeader(
        std::FILE* out,
        const AuthenticatedNavigationRecords& records)
    {
        WriteHeaderStyleLine(out,
            "     4.02           N: GNSS NAV DATA    E: GALILEO",
            "RINEX VERSION / TYPE");

        char program_line[128]{};
        const std::string utc_date = CurrentUtcRinexDate();
        std::snprintf(program_line,
            sizeof(program_line),
            "%-20.20s%-20.20s%-20.20s",
            "OSNMALIB",
            "OSNMA",
            utc_date.c_str());
        WriteHeaderStyleLine(out, program_line, "PGM / RUN BY / DATE");

        WriteHeaderStyleLine(out,
            "GALILEO I/NAV DATA AUTHENTICATED BY OSNMA",
            "COMMENT");
        WriteHeaderStyleLine(out,
            "RINEX 4.02 EPH, ION NEQUICK-G AND STO RECORDS",
            "COMMENT");
        WriteHeaderStyleLine(out,
            "ONLY VALID AUTHENTICATED NAVIGATION DATA ARE WRITTEN",
            "COMMENT");

        for (const GalileoAuthenticatedTiming& timing : records.timing)
        {
            if (!timing.utc_valid)
                continue;

            char content[160]{};
            /* See the RINEX 3 header writer: WN_LSF is modulo 256 and may
               describe a historical event, so only DeltaT_LS is unambiguous. */
            std::snprintf(content,
                sizeof(content),
                "%6d",
                timing.utc.DeltaT_LS);
            WriteHeaderStyleLine(out, content, "LEAP SECONDS");
            break;
        }

        WriteHeaderStyleLine(out, "", "END OF HEADER");
    }

    bool WriteAuthenticatedNavigationRinex4File(
        const AuthenticatedNavigationRecords& records,
        const char* prefix,
        std::string& filename_written,
        Rinex4WriteCounts& counts)
    {
        filename_written.clear();
        counts = Rinex4WriteCounts{};

        if (prefix == nullptr || prefix[0] == '\0')
            return false;

        const std::filesystem::path filename =
            MakeRinex4OutputFilename(prefix);

        std::error_code ec{};
        const std::filesystem::path parent = filename.parent_path();
        if (!parent.empty())
            std::filesystem::create_directories(parent, ec);

        if (ec)
            return false;

        std::FILE* out = OpenTextFileForWriting(filename);
        if (out == nullptr)
            return false;

        WriteRinex4FileHeader(out, records);

        std::vector<Rinex4Event> events{};
        events.reserve(records.ced_status.size() * 2u +
            records.timing.size() * 2u);

        for (std::size_t i = 0; i < records.ced_status.size(); ++i)
        {
            const GalileoAuthenticatedCedStatus& ced =
                records.ced_status[i];

            if (ced.ephemeris_valid)
            {
                events.push_back(Rinex4Event{
                    AbsoluteGstSeconds(PreferredPageEpoch(
                        ced.ephemeris_transmission_time,
                        ced.navigation_time)),
                    ced.prn,
                    Rinex4RecordKind::Ephemeris,
                    i});
            }

            if (ced.ionosphere_valid)
            {
                events.push_back(Rinex4Event{
                    AbsoluteGstSeconds(PreferredPageEpoch(
                        ced.wt5_page_time,
                        ced.navigation_time)),
                    ced.prn,
                    Rinex4RecordKind::Ionosphere,
                    i});
            }
        }

        for (std::size_t i = 0; i < records.timing.size(); ++i)
        {
            const GalileoAuthenticatedTiming& timing = records.timing[i];

            if (timing.utc_valid)
            {
                events.push_back(Rinex4Event{
                    AbsoluteGstSeconds(PreferredPageEpoch(
                        timing.wt6_page_time,
                        timing.navigation_time)),
                    timing.prn,
                    Rinex4RecordKind::UtcOffset,
                    i});
            }

            if (timing.ggto_valid)
            {
                events.push_back(Rinex4Event{
                    AbsoluteGstSeconds(PreferredPageEpoch(
                        timing.wt10_page_time,
                        timing.navigation_time)),
                    timing.prn,
                    Rinex4RecordKind::GgtoOffset,
                    i});
            }
        }

        std::stable_sort(events.begin(), events.end(),
            [](const Rinex4Event& a, const Rinex4Event& b)
            {
                if (a.absolute_gst_seconds != b.absolute_gst_seconds)
                    return a.absolute_gst_seconds < b.absolute_gst_seconds;

                if (a.prn != b.prn)
                    return a.prn < b.prn;

                if (a.kind != b.kind)
                {
                    return static_cast<int32_t>(a.kind) <
                        static_cast<int32_t>(b.kind);
                }

                return a.record_index < b.record_index;
            });

        bool have_last_iono = false;
        GALIonoDecodedType last_iono{};

        bool have_last_utc = false;
        GalileoAuthenticatedTiming last_utc{};

        bool have_last_ggto = false;
        GalileoAuthenticatedTiming last_ggto{};

        for (const Rinex4Event& event : events)
        {
            switch (event.kind)
            {
            case Rinex4RecordKind::Ephemeris:
            {
                const GalileoAuthenticatedCedStatus& ced =
                    records.ced_status[event.record_index];
                if (WriteAuthenticatedCedAsRinex4Ephemeris(out, ced))
                    ++counts.ephemeris;
                break;
            }

            case Rinex4RecordKind::Ionosphere:
            {
                const GalileoAuthenticatedCedStatus& ced =
                    records.ced_status[event.record_index];

                if (have_last_iono &&
                    SameIonosphereModel(last_iono, ced.ionosphere))
                {
                    break;
                }

                if (WriteAuthenticatedCedAsRinex4Ionosphere(out, ced))
                {
                    last_iono = ced.ionosphere;
                    have_last_iono = true;
                    ++counts.ionosphere;
                }
                break;
            }

            case Rinex4RecordKind::UtcOffset:
            {
                const GalileoAuthenticatedTiming& timing =
                    records.timing[event.record_index];

                if (have_last_utc && SameUtcOffset(last_utc, timing))
                    break;

                if (WriteAuthenticatedTimingAsRinex4UtcOffset(out, timing))
                {
                    last_utc = timing;
                    have_last_utc = true;
                    ++counts.utc_offset;
                }
                break;
            }

            case Rinex4RecordKind::GgtoOffset:
            {
                const GalileoAuthenticatedTiming& timing =
                    records.timing[event.record_index];

                if (have_last_ggto && SameGgtoOffset(last_ggto, timing))
                    break;

                if (WriteAuthenticatedTimingAsRinex4GgtoOffset(out, timing))
                {
                    last_ggto = timing;
                    have_last_ggto = true;
                    ++counts.ggto_offset;
                }
                break;
            }
            }
        }

        const bool close_ok = (std::fclose(out) == 0);
        if (!close_ok)
            return false;

        filename_written = filename.string();
        return true;
    }
}

static void PrintUsage(const char* exe_name)
{
    const char* exe = (exe_name != nullptr && exe_name[0] != '\0')
        ? exe_name
        : "osnma_test";

    printf("Usage:\n");
    printf("\n");
    printf("  Official EUSPA/GSC test vector, default configuration_1:\n");
    printf("    %s -tv <Test_vectors_root>\n", exe);
    printf("\n");
    printf("  Official EUSPA/GSC test vector, explicit scenario and CSV file:\n");
    printf("    %s -tv <Test_vectors_root> <scenario> <csv_file>\n", exe);
    printf("\n");
    printf("  JSONL/live-style input with explicit XML crypto material:\n");
    printf("    %s -json <file.jsonl> <MerkleTree.xml> <PublicKey.xml> [options]\n", exe);
    printf("      --print-nav\n");
    printf("          Appends the authenticated navigation comparison dump to stdout.\n");
    printf("      --rinex-prefix <prefix>\n");
    printf("          Writes a dedicated RINEX 3.05 file named <prefix>_osnma_nav.rnx.\n");
    printf("      --rinex4-prefix <prefix>\n");
    printf("          Writes a dedicated RINEX 4.02 file named <prefix>_osnma_nav4.rnx.\n");
    printf("      --pegasus-prefix <prefix>\n");
    printf("          Writes <prefix>_E_INAV.eph/.iono/.dtime/.log.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -tv \"D:\\data\\osnma\\Test_vectors\"\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml --print-nav\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml --rinex-prefix D:\\data\\osnma\\week_1397\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml --rinex4-prefix D:\\data\\osnma\\week_1397\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml --pegasus-prefix D:\\data\\osnma\\week_1397\n", exe);
}

static void PrintXmlMaterialStats(const OsnmaXmlMaterialLoader::Stats& s)
{
    printf("\nXML crypto material:\n");
    printf("  merkle_root_loaded=%d public_keys_loaded=%d\n",
           s.merkle_root_loaded,
           s.public_keys_loaded);
    printf("  merkle_tree_id=%d current_pkid=%d new_pkid=%d new_merkle_tree_id=%d\n",
           s.merkle_tree_id,
           s.current_pkid,
           s.new_pkid,
           s.new_merkle_tree_id);
}

static void PrintOfficialReaderStats(const OsnmaOfficialTestVectorReader::Stats& s)
{
    printf("\nOfficial CSV reader statistics:\n");
    printf("  csv_row_count=%d satellite_count=%d page_count_per_satellite=%d page_count=%d fed_page_count=%d\n",
           s.csv_row_count,
           s.satellite_count,
           s.page_count_per_satellite,
           s.page_count,
           s.fed_page_count);
    printf("  malformed_row_count=%d malformed_hex_count=%d inconsistent_length_count=%d\n",
           s.malformed_row_count,
           s.malformed_hex_count,
           s.inconsistent_length_count);

    if (s.has_start_time)
    {
        printf("  start_time WN=%d TOW=%.0f\n",
               s.start_time.wn,
               s.start_time.tow);
    }

    printf("  WT count:");
    for (int32_t i = 0; i < static_cast<int32_t>(s.wt_count.size()); ++i)
    {
        if (s.wt_count[i] > 0)
            printf(" WT%d=%d", i, s.wt_count[i]);
    }
    printf("\n");
}

static void PrintRawJsonReaderStats(const OsnmaRawJsonReader::Stats& s)
{
    printf("\nJSONL reader statistics:\n");
    printf("  lines=%d subframes=%d pages=%d fed_page_count=%d\n",
           s.line_count,
           s.subframe_count,
           s.page_count,
           s.fed_page_count);
    printf("  malformed_lines=%d malformed_hex=%d missing_e1b_array=%d null_pages=%d\n",
           s.malformed_line_count,
           s.malformed_hex_count,
           s.missing_e1b_array_count,
           s.null_page_count);

    printf("  reorder_buffered_subframes=%d reorder_flushed_subframes=%d reorder_max_buffered_subframes=%d\n",
           s.reorder_buffered_subframes,
           s.reorder_flushed_subframes,
           s.reorder_max_buffered_subframes);
    printf("  reorder_out_of_order_subframes=%d reorder_max_lateness_s=%d\n",
           s.reorder_out_of_order_subframes,
           s.reorder_max_lateness_s);

    printf("  WT count:");
    for (int32_t i = 0; i < static_cast<int32_t>(s.wt_count.size()); ++i)
    {
        if (s.wt_count[i] > 0)
            printf(" WT%d=%d", i, s.wt_count[i]);
    }
    printf("\n");
}

static void PrintReasonCounts(const OsnmaEngine::Statistics& s)
{
    printf("\nReason/count details:\n");

    printf("  dsm_decode_failed_reason_count:");
    for (int32_t i = 0;
        i < static_cast<int32_t>(s.dsm_decode_failed_reason_count.size());
        ++i)
    {
        if (s.dsm_decode_failed_reason_count[i] > 0)
            printf(" %d=%lld", i, static_cast<long long>(s.dsm_decode_failed_reason_count[i]));
    }
    printf("\n");

    printf("  kroot_failed_reason_count:");
    for (int32_t i = 0;
        i < static_cast<int32_t>(s.kroot_failed_reason_count.size());
        ++i)
    {
        if (s.kroot_failed_reason_count[i] > 0)
            printf(" %d=%lld", i, static_cast<long long>(s.kroot_failed_reason_count[i]));
    }
    printf("\n");

    printf("  pkr_failed_reason_count:");
    for (int32_t i = 0;
        i < static_cast<int32_t>(s.pkr_failed_reason_count.size());
        ++i)
    {
        if (s.pkr_failed_reason_count[i] > 0)
            printf(" %d=%lld", i, static_cast<long long>(s.pkr_failed_reason_count[i]));
    }
    printf("\n");

    printf("  DSM ID 13 BID count:");
    for (int32_t bid = 0; bid < 16; ++bid)
    {
        if (s.dsm_bid_count[13][bid] > 0)
            printf(" %d=%lld", bid, static_cast<long long>(s.dsm_bid_count[13][bid]));
    }
    printf("\n");
}

static void PrintOsnmaEngineStatistics(const OsnmaEngine::Statistics& s)
{
    printf("\nOSNMA engine statistics:\n");

    printf("  navigation_pages_received=%lld\n",
           static_cast<long long>(s.navigation_pages_received));

    printf("  subframes_processed=%lld\n",
           static_cast<long long>(s.subframes_processed));
    printf("  subframes_without_osnma=%lld\n",
           static_cast<long long>(s.subframes_without_osnma));

    printf("\nDSM:\n");
    printf("  dsm_blocks_received=%lld\n",
           static_cast<long long>(s.dsm_blocks_received));
    printf("  dsm_messages_completed=%lld\n",
           static_cast<long long>(s.dsm_messages_completed));
    printf("  dsm_decode_ok=%lld\n",
           static_cast<long long>(s.dsm_decode_ok));
    printf("  dsm_decode_failed=%lld\n",
           static_cast<long long>(s.dsm_decode_failed));
    printf("  dsm_kroot_assemblies_expired=%lld dsm_pkr_assemblies_expired=%lld\n",
           static_cast<long long>(s.dsm_kroot_assemblies_expired),
           static_cast<long long>(s.dsm_pkr_assemblies_expired));
    printf("  dsm_failures_nonfatal=%lld mack_parse_attempted_after_dsm_failure=%lld mack_parse_ok_after_dsm_failure=%lld\n",
           static_cast<long long>(s.dsm_failures_nonfatal),
           static_cast<long long>(s.mack_parse_attempted_after_dsm_failure),
           static_cast<long long>(s.mack_parse_ok_after_dsm_failure));

    printf("  dsm_id_count:");
    for (int32_t i = 0; i < static_cast<int32_t>(s.dsm_id_count.size()); ++i)
    {
        if (s.dsm_id_count[i] > 0)
        {
            printf(" %d=%lld",
                   i,
                   static_cast<long long>(s.dsm_id_count[i]));
        }
    }
    printf("\n");

    printf("  dsm_completed_id_count:");
    for (int32_t i = 0; i < static_cast<int32_t>(s.dsm_completed_id_count.size()); ++i)
    {
        if (s.dsm_completed_id_count[i] > 0)
        {
            printf(" %d=%lld",
                   i,
                   static_cast<long long>(s.dsm_completed_id_count[i]));
        }
    }
    printf("\n");

    printf("\nPKR/KROOT/TESLA:\n");
    printf("  pkr_received=%lld pkr_verified=%lld pkr_failed=%lld\n",
           static_cast<long long>(s.pkr_received),
           static_cast<long long>(s.pkr_verified),
           static_cast<long long>(s.pkr_failed));
    printf("  kroot_received=%lld kroot_verified=%lld kroot_failed=%lld\n",
           static_cast<long long>(s.kroot_received),
           static_cast<long long>(s.kroot_verified),
           static_cast<long long>(s.kroot_failed));
    printf("  tesla_initialized=%lld tesla_init_failed=%lld\n",
           static_cast<long long>(s.tesla_initialized),
           static_cast<long long>(s.tesla_init_failed));
    printf("  disclosed_keys_verified=%lld disclosed_keys_new=%lld disclosed_keys_ignored_same_or_older=%lld disclosed_keys_failed=%lld\n",
           static_cast<long long>(s.disclosed_keys_verified),
           static_cast<long long>(s.disclosed_keys_new),
           static_cast<long long>(s.disclosed_keys_ignored_same_or_older),
           static_cast<long long>(s.disclosed_keys_failed));
    printf("  subframes_waiting_for_kroot=%lld\n",
           static_cast<long long>(s.subframes_waiting_for_kroot));

    printf("\nMACK/pending verification:\n");
    printf("  mack_parse_ok=%lld mack_parse_failed=%lld all_zero_macks_rejected=%lld\n",
           static_cast<long long>(s.mack_parse_ok),
           static_cast<long long>(s.mack_parse_failed),
           static_cast<long long>(s.all_zero_macks_rejected));
    printf("  macks_added_pending=%lld\n",
           static_cast<long long>(s.macks_added_pending));
    printf("  pending_macks_current=%d pending_macks_max_seen=%d\n",
           s.pending_macks_current,
           s.pending_macks_max_seen);
    printf("  pending_macks_overwritten=%lld pending_macks_cleaned=%lld\n",
           static_cast<long long>(s.pending_macks_overwritten),
           static_cast<long long>(s.pending_macks_cleaned));
    printf("  pending_verification_runs=%lld pending_macks_checked=%lld\n",
           static_cast<long long>(s.pending_verification_runs),
           static_cast<long long>(s.pending_macks_checked));
    printf("  pending_waiting_for_key=%lld pending_missing_navdata=%lld\n",
           static_cast<long long>(s.pending_waiting_for_key),
           static_cast<long long>(s.pending_missing_navdata));
    printf("  pending_macks_verified_ok=%lld pending_macks_terminal_failed=%lld\n",
           static_cast<long long>(s.pending_macks_verified_ok),
           static_cast<long long>(s.pending_macks_terminal_failed));
    printf("  pending_macks_skipped_macseq=%lld pending_macks_failed_tag=%lld pending_macks_failed_other=%lld\n",
           static_cast<long long>(s.pending_macks_skipped_macseq),
           static_cast<long long>(s.pending_macks_failed_tag),
           static_cast<long long>(s.pending_macks_failed_other));
    printf("  auth_success=%lld authenticated_tag_success=%lld authenticated_auth_bits_total=%lld\n",
           static_cast<long long>(s.auth_success),
           static_cast<long long>(s.authenticated_tag_success),
           static_cast<long long>(s.authenticated_auth_bits_total));
    printf("  authenticated_object_updates=%lld ced_status=%lld timing=%lld slow_mac=%lld\n",
           static_cast<long long>(s.authenticated_object_updates),
           static_cast<long long>(s.authenticated_ced_status_objects),
           static_cast<long long>(s.authenticated_timing_objects),
           static_cast<long long>(s.authenticated_slow_mac_objects));
    printf("  authenticated_output ced_status=%lld timing=%lld eph=%lld iono=%lld utc=%lld ggto=%lld\n",
           static_cast<long long>(s.authenticated_ced_status_output),
           static_cast<long long>(s.authenticated_timing_output),
           static_cast<long long>(s.authenticated_ephemeris_output),
           static_cast<long long>(s.authenticated_ionosphere_output),
           static_cast<long long>(s.authenticated_utc_output),
           static_cast<long long>(s.authenticated_ggto_output));
}

static bool RunSelfTests()
{
    const OsnmaSelfTest::Result self =
        OsnmaSelfTest::RunAll();

    if (!self.passed)
    {
        printf("OSNMA self-test failed: %s\n",
               self.first_failure.data());
        return false;
    }

    printf("OSNMA self-test passed: %d tests\n",
           self.test_count);
    return true;
}

static int RunOfficialTestVectorMode(const char* test_vectors_root_arg,
    const char* scenario_arg,
    const char* csv_file_arg)
{
    if (test_vectors_root_arg == nullptr || test_vectors_root_arg[0] == '\0')
    {
        printf("Missing Test_vectors root directory.\n");
        return 1;
    }

    const char* scenario =
        (scenario_arg != nullptr && scenario_arg[0] != '\0')
        ? scenario_arg
        : "configuration_1";

    const char* csv_file =
        (csv_file_arg != nullptr && csv_file_arg[0] != '\0')
        ? csv_file_arg
        : "16_AUG_2023_GST_05_00_01.csv";

    const std::filesystem::path test_vectors_root(test_vectors_root_arg);
    const std::filesystem::path csv_path =
        test_vectors_root /
        "osnma_test_vectors" /
        scenario /
        csv_file;

    const std::string csv_path_string = csv_path.string();

    printf("\nMode: official test vector\n");
    printf("  Test_vectors root: %s\n", test_vectors_root_arg);
    printf("  scenario: %s\n", scenario);
    printf("  CSV: %s\n", csv_path_string.c_str());

    auto auth_ptr = std::make_unique<OsnmaAuthenticator>();
    OsnmaAuthenticator& auth = *auth_ptr;

    OsnmaXmlMaterialLoader::Stats crypto_stats{};

    if (!OsnmaXmlMaterialLoader::LoadOfficialTestVectorMaterial(
        csv_path_string.c_str(),
        auth,
        &crypto_stats))
    {
        printf("Failed to load official OSNMA XML crypto material.\n");
        return 1;
    }

    PrintXmlMaterialStats(crypto_stats);

    OsnmaOfficialTestVectorReader::Stats reader_stats{};

    const bool ok =
        OsnmaOfficialTestVectorReader::FeedFileToAuthenticator(
            csv_path_string.c_str(),
            auth,
            &reader_stats,
            NavSignalSource::Unknown,
            0,
            true,
            1);

    if (!ok)
    {
        printf("Official CSV reader failed.\n");
        return 1;
    }

    PrintOfficialReaderStats(reader_stats);

    const OsnmaEngine::Statistics& engine_stats =
        auth.GetEngineStatistics();

    PrintReasonCounts(engine_stats);
    PrintOsnmaEngineStatistics(engine_stats);

    printf("Done.\n");
    return 0;
}

static int RunJsonMode(const char* jsonl_filename,
    const char* merkle_tree_xml,
    const char* public_key_xml,
    bool print_navigation,
    const char* rinex_prefix,
    const char* rinex4_prefix,
    const char* pegasus_prefix)
{
    if (jsonl_filename == nullptr || jsonl_filename[0] == '\0' ||
        merkle_tree_xml == nullptr || merkle_tree_xml[0] == '\0' ||
        public_key_xml == nullptr || public_key_xml[0] == '\0')
    {
        printf("Missing JSON/XML input file.\n");
        return 1;
    }

    printf("\nMode: JSONL/live-style input\n");
    printf("  JSONL: %s\n", jsonl_filename);
    printf("  Merkle tree XML: %s\n", merkle_tree_xml);
    printf("  Public key XML: %s\n", public_key_xml);

    auto auth_ptr = std::make_unique<OsnmaAuthenticator>();
    OsnmaAuthenticator& auth = *auth_ptr;

    auth.SetNavTimingMode(NavTimingMode::Standard);

    if (!OsnmaXmlMaterialLoader::LoadMerkleTreeXmlToAuthenticator(
        merkle_tree_xml,
        auth))
    {
        printf("Failed to load Merkle tree XML.\n");
        return 1;
    }

    if (!OsnmaXmlMaterialLoader::LoadPublicKeyXmlToAuthenticator(
        public_key_xml,
        auth))
    {
        printf("Failed to load public key XML.\n");
        return 1;
    }

    OsnmaRawJsonReader::Stats reader_stats{};

    const bool ok =
        OsnmaRawJsonReader::FeedFileToAuthenticator(
            jsonl_filename,
            auth,
            &reader_stats,
            NavSignalSource::Unknown,
            0,
            true,
            1);

    if (!ok)
    {
        printf("JSONL reader failed.\n");
        return 1;
    }

    PrintRawJsonReaderStats(reader_stats);

    const OsnmaEngine::Statistics& engine_stats =
        auth.GetEngineStatistics();

    PrintReasonCounts(engine_stats);
    PrintOsnmaEngineStatistics(engine_stats);

    if (print_navigation ||
        (rinex_prefix != nullptr && rinex_prefix[0] != '\0') ||
        (rinex4_prefix != nullptr && rinex4_prefix[0] != '\0'))
    {
        const AuthenticatedNavigationRecords records =
            CollectAuthenticatedNavigation(auth);

        if (rinex_prefix != nullptr && rinex_prefix[0] != '\0')
        {
            std::string rinex_filename{};
            int32_t rinex_record_count = 0;

            if (!WriteAuthenticatedNavigationRinexFile(
                records,
                rinex_prefix,
                rinex_filename,
                rinex_record_count))
            {
                printf("Failed to write the RINEX navigation file for prefix: %s\n",
                    rinex_prefix);
                return 1;
            }

            printf("\nRINEX navigation output:\n");
            printf("  file=%s\n", rinex_filename.c_str());
            printf("  authenticated_ephemeris_records=%d\n",
                rinex_record_count);
        }

        if (rinex4_prefix != nullptr && rinex4_prefix[0] != '\0')
        {
            std::string rinex4_filename{};
            Rinex4WriteCounts rinex4_counts{};

            if (!WriteAuthenticatedNavigationRinex4File(
                records,
                rinex4_prefix,
                rinex4_filename,
                rinex4_counts))
            {
                printf("Failed to write the RINEX 4.02 navigation file for prefix: %s\n",
                    rinex4_prefix);
                return 1;
            }

            printf("\nRINEX 4.02 navigation output:\n");
            printf("  file=%s\n", rinex4_filename.c_str());
            printf("  authenticated_ephemeris_records=%d\n",
                rinex4_counts.ephemeris);
            printf("  ionosphere_records=%d utc_offset_records=%d ggto_offset_records=%d\n",
                rinex4_counts.ionosphere,
                rinex4_counts.utc_offset,
                rinex4_counts.ggto_offset);
        }

        if (print_navigation)
            PrintAuthenticatedNavigationDump(records);
    }

    if (pegasus_prefix != nullptr && pegasus_prefix[0] != '\0')
    {
        PegasusCsvWriter::Result pegasus_result{};
        if (!PegasusCsvWriter::Write(pegasus_prefix,
            auth,
            reader_stats,
            pegasus_result))
        {
            printf("Failed to write Pegasus files for prefix: %s\n",
                pegasus_prefix);
            return 1;
        }

        printf("\nPegasus navigation output:\n");
        printf("  eph=%s rows=%d\n",
            pegasus_result.eph_filename.c_str(),
            pegasus_result.eph_rows);
        printf("  iono=%s rows=%d\n",
            pegasus_result.iono_filename.c_str(),
            pegasus_result.iono_rows);
        printf("  dtime=%s rows=%d\n",
            pegasus_result.dtime_filename.c_str(),
            pegasus_result.dtime_rows);
        printf("  log=%s rows=%d\n",
            pegasus_result.log_filename.c_str(),
            pegasus_result.log_rows);
    }

    printf("Done.\n");
    return 0;
}

int main(int argc, char** argv)
{
    if (argc <= 1 ||
        std::strcmp(argv[1], "-h") == 0 ||
        std::strcmp(argv[1], "--help") == 0 ||
        std::strcmp(argv[1], "/?") == 0)
    {
        PrintUsage((argc > 0) ? argv[0] : nullptr);
        return (argc <= 1) ? 1 : 0;
    }

    if (!RunSelfTests())
        return 1;

    if (std::strcmp(argv[1], "-tv") == 0)
    {
        if (argc != 3 && argc != 5)
        {
            printf("Invalid -tv arguments.\n\n");
            PrintUsage(argv[0]);
            return 1;
        }

        const char* test_vectors_root = argv[2];
        const char* scenario = (argc == 5) ? argv[3] : nullptr;
        const char* csv_file = (argc == 5) ? argv[4] : nullptr;

        return RunOfficialTestVectorMode(test_vectors_root,
            scenario,
            csv_file);
    }

    if (std::strcmp(argv[1], "-json") == 0)
    {
        if (argc < 5)
        {
            printf("Invalid -json arguments.\n\n");
            PrintUsage(argv[0]);
            return 1;
        }

        bool print_navigation = false;
        const char* rinex_prefix = nullptr;
        const char* rinex4_prefix = nullptr;
        const char* pegasus_prefix = nullptr;

        for (int32_t arg_index = 5; arg_index < argc; ++arg_index)
        {
            if (std::strcmp(argv[arg_index], "--print-nav") == 0)
            {
                print_navigation = true;
                continue;
            }

            if (std::strcmp(argv[arg_index], "--rinex-prefix") == 0)
            {
                if (arg_index + 1 >= argc)
                {
                    printf("Missing value after --rinex-prefix.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }

                rinex_prefix = argv[++arg_index];
                if (rinex_prefix[0] == '\0')
                {
                    printf("Empty --rinex-prefix value.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }
                continue;
            }

            if (std::strcmp(argv[arg_index], "--rinex4-prefix") == 0)
            {
                if (arg_index + 1 >= argc)
                {
                    printf("Missing value after --rinex4-prefix.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }

                rinex4_prefix = argv[++arg_index];
                if (rinex4_prefix[0] == '\0')
                {
                    printf("Empty --rinex4-prefix value.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }
                continue;
            }

            if (std::strcmp(argv[arg_index], "--pegasus-prefix") == 0)
            {
                if (arg_index + 1 >= argc)
                {
                    printf("Missing value after --pegasus-prefix.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }

                pegasus_prefix = argv[++arg_index];
                if (pegasus_prefix[0] == '\0')
                {
                    printf("Empty --pegasus-prefix value.\n\n");
                    PrintUsage(argv[0]);
                    return 1;
                }
                continue;
            }

            printf("Unknown -json option: %s\n\n", argv[arg_index]);
            PrintUsage(argv[0]);
            return 1;
        }

        return RunJsonMode(argv[2], argv[3], argv[4],
            print_navigation,
            rinex_prefix,
            rinex4_prefix,
            pegasus_prefix);
    }

    printf("Unknown option: %s\n\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
}
