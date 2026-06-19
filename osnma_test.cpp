#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

#include "osnma_authenticator.h"
#include "osnma_raw_json_reader.h"
#include "osnma_official_test_vector_reader.h"
#include "osnma_xml_material_loader.h"
#include "osnma_self_test.h"

// -tv "D:\data\osnma\Test_vectors" > d:\data\osnma\out.txt
// -tv "D:\data\osnma\Test_vectors" configuration_1 16_AUG_2023_GST_05_00_01.csv > d:\data\osnma\out.txt
// -json D:\data\osnma\week_1397_1h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml > d:\data\osnma\jsonout.txt
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml > d:\data\osnma\jsonout.txt
// -json D:\data\osnma\week_1397_24h.jsonl D:\data\osnma\OSNMA_MerkleTree_20251210100000_newPKID_2.xml D:\data\osnma\OSNMA_PublicKey_20251210100000_newPKID_2.xml --print-nav > d:\data\osnma\jsonout_nav.txt

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

    void PrintRinexFour(double a,
        double b,
        double c,
        double d)
    {
        const std::string fa = RinexDouble(a);
        const std::string fb = RinexDouble(b);
        const std::string fc = RinexDouble(c);
        const std::string fd = RinexDouble(d);

        printf("    %s%s%s%s\n",
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

    double RinexTransmissionTime(
        const GalileoAuthenticatedCedStatus& data)
    {
        if (!IsTimeValid(data.wt1_page_time) ||
            data.ephemeris.WNToe > static_cast<unsigned long>(INT32_MAX))
        {
            return RINEX_UNKNOWN_TRANSMISSION_TIME;
        }

        const int32_t toe_gst_week =
            static_cast<int32_t>(data.ephemeris.WNToe);

        return data.wt1_page_time.tow +
            static_cast<double>(data.wt1_page_time.wn - toe_gst_week) *
            SECONDS_PER_WEEK;
    }

    void PrintHeaderStyleLine(const std::string& content,
        const char* label)
    {
        printf("%-60.60s%-20.20s\n",
            content.c_str(),
            label != nullptr ? label : "");
    }

    void PrintAuthenticatedCedAsRinex(
        const GalileoAuthenticatedCedStatus& data)
    {
        const GALEphDecodedType& eph = data.ephemeris;

        printf("# OSNMA E%02d NAV_GST=%d/%.0f AUTH_GST=%d/%.0f "
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

        if (!data.ephemeris_valid)
        {
            printf("# RINEX record skipped: ephemeris_valid=0 "
                   "iodnav_consistent=%d svid_matches_prn=%d\n",
                data.iodnav_consistent ? 1 : 0,
                data.svid_matches_prn ? 1 : 0);
            return;
        }

        CalendarFields epoch{};

        if (!GstToCalendar(
            static_cast<int32_t>(eph.WNToc),
            static_cast<double>(eph.Toc),
            epoch))
        {
            printf("# RINEX record skipped: invalid Toc epoch\n");
            return;
        }

        const std::string af0 = RinexDouble(eph.af0);
        const std::string af1 = RinexDouble(eph.af1);
        const std::string af2 = RinexDouble(eph.af2);

        printf("E%02d %04d %02d %02d %02d %02d %02d%s%s%s\n",
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

        PrintRinexFour(
            static_cast<double>(eph.IODNav),
            eph.Crs,
            eph.DeltaN,
            eph.M0);

        PrintRinexFour(
            eph.Cuc,
            eph.Ecc,
            eph.Cus,
            eph.sqrtA);

        PrintRinexFour(
            static_cast<double>(eph.Toe),
            eph.Cic,
            eph.Omega0,
            eph.Cis);

        PrintRinexFour(
            eph.i0,
            eph.Crc,
            eph.Omega,
            eph.OmegaDot);

        PrintRinexFour(
            eph.IDot,
            static_cast<double>(eph.DataSources),
            static_cast<double>(GstWeekToRinexWeek(
                static_cast<int32_t>(eph.WNToe))),
            0.0);

        PrintRinexFour(
            SisaIndexToMeters(data.sisa),
            static_cast<double>(eph.SVHealth),
            eph.BGD_L1E5a,
            eph.BGD_L1E5b);

        PrintRinexFour(
            RinexTransmissionTime(data),
            0.0,
            0.0,
            0.0);

        if (data.ionosphere_valid)
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

            PrintHeaderStyleLine(content, "IONOSPHERIC CORR");
            printf("# IONO E%02d storm_flags=0x%02X\n",
                data.prn,
                static_cast<unsigned>(data.ionosphere.StormFlags));
        }
    }

    void PrintAuthenticatedTimingAsRinexHeader(
        const GalileoAuthenticatedTiming& data)
    {
        printf("# OSNMA-TIME E%02d NAV_GST=%d/%.0f AUTH_GST=%d/%.0f "
               "AUTHBITS=%lld\n",
            data.prn,
            data.navigation_time.wn,
            data.navigation_time.tow,
            data.authentication_time.wn,
            data.authentication_time.tow,
            static_cast<long long>(data.auth_bits));

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

            PrintHeaderStyleLine(content, "TIME SYSTEM CORR");

            printf("# LEAP E%02d current=%d future=%d WN_LSF_GST=%d "
                   "WN_LSF_RINEX=%d DN=%d\n",
                data.prn,
                data.utc.DeltaT_LS,
                data.utc.DeltaT_LSF,
                data.utc.WN_LSF,
                GstWeekToRinexWeek(data.utc.WN_LSF),
                data.utc.DN_LSF);
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

            PrintHeaderStyleLine(content, "TIME SYSTEM CORR");
        }
    }

    void PrintAuthenticatedNavigationDump(OsnmaAuthenticator& auth)
    {
        const int32_t ced_queued = auth.AuthenticatedCedStatusCount();
        const int32_t timing_queued = auth.AuthenticatedTimingCount();

        printf("\n===== BEGIN AUTHENTICATED GALILEO RINEX 3.05 COMPARISON DUMP =====\n");
        printf("# CED/status records queued: %d\n", ced_queued);
        printf("# Timing records queued: %d\n", timing_queued);
        printf("# Galileo week values in the RINEX records are GST week + 1024.\n");
        printf("# Data source 513 means I/NAV E1-B plus E5b/E1 clock parameters.\n");
        printf("# Lines beginning with # are diagnostics, not RINEX records.\n");

        int32_t ced_printed = 0;
        int32_t ced_skipped = 0;
        GalileoAuthenticatedCedStatus ced{};

        while (auth.PopAuthenticatedCedStatus(ced))
        {
            if (ced.ephemeris_valid)
                ++ced_printed;
            else
                ++ced_skipped;

            PrintAuthenticatedCedAsRinex(ced);
        }

        printf("\n# AUTHENTICATED UTC/GGTO HEADER-STYLE RECORDS\n");

        int32_t timing_printed = 0;
        GalileoAuthenticatedTiming timing{};

        while (auth.PopAuthenticatedTiming(timing))
        {
            ++timing_printed;
            PrintAuthenticatedTimingAsRinexHeader(timing);
        }

        printf("# Dump summary: ced_printed=%d ced_skipped=%d timing_printed=%d\n",
            ced_printed,
            ced_skipped,
            timing_printed);
        printf("===== END AUTHENTICATED GALILEO RINEX 3.05 COMPARISON DUMP =====\n");
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
    printf("    %s -json <file.jsonl> <MerkleTree.xml> <PublicKey.xml> [--print-nav]\n", exe);
    printf("      --print-nav appends authenticated navigation data in RINEX 3.05 field order.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -tv \"D:\\data\\osnma\\Test_vectors\"\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml --print-nav\n", exe);
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

    printf("\nDSM:\n");
    printf("  dsm_blocks_received=%lld\n",
           static_cast<long long>(s.dsm_blocks_received));
    printf("  dsm_messages_completed=%lld\n",
           static_cast<long long>(s.dsm_messages_completed));
    printf("  dsm_decode_ok=%lld\n",
           static_cast<long long>(s.dsm_decode_ok));
    printf("  dsm_decode_failed=%lld\n",
           static_cast<long long>(s.dsm_decode_failed));
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
    printf("  mack_parse_ok=%lld mack_parse_failed=%lld\n",
           static_cast<long long>(s.mack_parse_ok),
           static_cast<long long>(s.mack_parse_failed));
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
    bool print_navigation)
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

    if (print_navigation)
        PrintAuthenticatedNavigationDump(auth);

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
        if (argc != 5 && argc != 6)
        {
            printf("Invalid -json arguments.\n\n");
            PrintUsage(argv[0]);
            return 1;
        }

        bool print_navigation = false;

        if (argc == 6)
        {
            if (std::strcmp(argv[5], "--print-nav") != 0)
            {
                printf("Unknown -json option: %s\n\n", argv[5]);
                PrintUsage(argv[0]);
                return 1;
            }

            print_navigation = true;
        }

        return RunJsonMode(argv[2], argv[3], argv[4],
            print_navigation);
    }

    printf("Unknown option: %s\n\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
}
