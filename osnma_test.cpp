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
    printf("    %s -json <file.jsonl> <MerkleTree.xml> <PublicKey.xml>\n", exe);
    printf("\n");
    printf("Examples:\n");
    printf("  %s -tv \"D:\\data\\osnma\\Test_vectors\"\n", exe);
    printf("  %s -json week_1397_24h.jsonl OSNMA_MerkleTree_20251210100000_newPKID_2.xml OSNMA_PublicKey_20251210100000_newPKID_2.xml\n", exe);
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
    const char* public_key_xml)
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
        if (argc != 5)
        {
            printf("Invalid -json arguments.\n\n");
            PrintUsage(argv[0]);
            return 1;
        }

        return RunJsonMode(argv[2], argv[3], argv[4]);
    }

    printf("Unknown option: %s\n\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
}
