#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <tuple>

#include "auth_record.h"
#include "galileo_auth_data_fifo.h"
#include "galileo_inav_page_parts.h"
#include "galileo_nav_candidate.h"
#include "nav_signal_source.h"
#include "osnma_dsm.h"
#include "osnma_dsm_content.h"
#include "osnma_mac_verifier.h"
#include "osnma_mack.h"
#include "osnma_subframe_assembler.h"
#include "osnma_tesla_chain.h"
#include "osnma_trust_store.h"
#include "osnma_types.h"

class OsnmaEngine
{
public:
    static constexpr int32_t MAX_AUTH_RECORDS_PER_SUBFRAME = 64;

    struct Result
    {
        AuthState state = AuthState::Unknown;
        AuthReason reason = AuthReason::WaitingForKey;

        int32_t auth_record_count = 0;
        std::array<AuthRecord, MAX_AUTH_RECORDS_PER_SUBFRAME> auth_records{};
    };

    struct Statistics
    {
        std::int64_t navigation_pages_received = 0;

        std::int64_t subframes_processed = 0;

        std::int64_t dsm_blocks_received = 0;
        std::int64_t dsm_messages_completed = 0;
        std::int64_t dsm_decode_ok = 0;
        std::int64_t dsm_decode_failed = 0;

        /*
            A DSM failure is non-fatal to the MACK carried by the same
            subframe when an older trusted KROOT is already available.
        */
        std::int64_t dsm_failures_nonfatal = 0;
        std::int64_t mack_parse_attempted_after_dsm_failure = 0;
        std::int64_t mack_parse_ok_after_dsm_failure = 0;
        std::array<std::int64_t, 16> dsm_id_count{};
        std::array<std::int64_t, 16> dsm_completed_id_count{};
        std::array<std::int64_t, 32> dsm_decode_failed_reason_count{};
        std::array<std::int64_t, 32> kroot_failed_reason_count{};
        std::array<std::int64_t, 32> pkr_failed_reason_count{};
        std::array<std::array<std::int64_t, 16>, 16> dsm_bid_count{};
        
        std::int64_t pkr_received = 0;
        std::int64_t pkr_verified = 0;
        std::int64_t pkr_failed = 0;

        std::int64_t kroot_received = 0;
        std::int64_t kroot_verified = 0;
        std::int64_t kroot_failed = 0;

        std::int64_t tesla_initialized = 0;
        std::int64_t tesla_init_failed = 0;
        std::int64_t disclosed_keys_verified = 0;
        std::int64_t disclosed_keys_new = 0;
        std::int64_t disclosed_keys_ignored_same_or_older = 0;
        std::int64_t disclosed_keys_failed = 0;

        std::int64_t subframes_waiting_for_kroot = 0;

        std::int64_t mack_parse_ok = 0;
        std::int64_t mack_parse_failed = 0;
        std::int64_t macks_added_pending = 0;

        std::int64_t pending_macks_overwritten = 0;
        std::int64_t pending_macks_cleaned = 0;
        std::int64_t pending_macks_verified_ok = 0;
        std::int64_t pending_macks_terminal_failed = 0;
        std::int64_t pending_macks_skipped_macseq = 0;
        std::int64_t pending_macks_failed_tag = 0;
        std::int64_t pending_macks_failed_other = 0;

        std::int64_t pending_verification_runs = 0;
        std::int64_t pending_macks_checked = 0;
        std::int64_t pending_waiting_for_key = 0;
        std::int64_t pending_missing_navdata = 0;

        std::int64_t auth_success = 0;
        std::int64_t authenticated_tag_success = 0;
        std::int64_t authenticated_auth_bits_total = 0;
        std::int64_t authenticated_object_updates = 0;
        std::int64_t authenticated_ced_status_objects = 0;
        std::int64_t authenticated_timing_objects = 0;
        std::int64_t authenticated_slow_mac_objects = 0;

        std::int64_t authenticated_ced_status_output = 0;
        std::int64_t authenticated_timing_output = 0;
        std::int64_t authenticated_ephemeris_output = 0;
        std::int64_t authenticated_ionosphere_output = 0;
        std::int64_t authenticated_utc_output = 0;
        std::int64_t authenticated_ggto_output = 0;

        int32_t pending_macks_current = 0;
        int32_t pending_macks_max_seen = 0;
    };

public:
    void Reset();

    void SetNavTimingMode(NavTimingMode mode);
    NavTimingMode GetNavTimingMode() const;

    bool SetMerkleRoot(const std::uint8_t* root_32_bytes);

    bool AddTrustedPublicKey(const OsnmaDsmPkr& public_key);

    bool FeedNavigationPage(const GalileoInavPageParts& page,
        AuthReason& reason_out);

    Result ProcessSubframe(const OsnmaSubframe& subframe,
        NavSignalSource source,
        int32_t raw_source);

    const Statistics& GetStatistics() const;

    bool PopAuthenticatedCedStatus(GalileoAuthenticatedCedStatus& data);
    bool PopAuthenticatedTiming(GalileoAuthenticatedTiming& data);

    int32_t AuthenticatedCedStatusCount() const;
    int32_t AuthenticatedTimingCount() const;

private:
    static constexpr int32_t MAX_PENDING_MACKS = 64;
    static constexpr double PENDING_MACK_LIFETIME_S = 900.0;

    struct PendingMack
    {
        bool valid = false;

        OsnmaMackMessage mack{};
        std::uint8_t nmas = 0;

        NavSignalSource source = NavSignalSource::Unknown;
        int32_t raw_source = 0;
    };

    struct AuthenticatedObjectState
    {
        std::int64_t auth_bits = 0;
    };

    using AuthenticatedObjectKey =
        std::tuple<int32_t, int32_t, std::uint64_t>;

private:
    Result MakePendingResult(const OsnmaSubframe& subframe,
        NavSignalSource source,
        int32_t raw_source,
        AuthReason reason) const;

    void AddPendingMack(const OsnmaMackMessage& mack,
        std::uint8_t nmas,
        NavSignalSource source,
        int32_t raw_source);

    void CleanupPendingMacks(const GnssTime& now);

    void RemovePendingMack(int32_t index);

    void UpdatePendingMackStatistics();

    void RegisterMacSuccesses(const OsnmaMacVerifier::Result& mac_result,
        const GnssTime& authentication_time,
        NavSignalSource source,
        int32_t raw_source);

    static bool IsSameSubframeTime(const GnssTime& a,
        const GnssTime& b);

    static GnssTime AddSecondsNormalized(const GnssTime& time,
        double seconds);

    Result ProcessMacksForDisclosedKey(const OsnmaDsmKroot& trusted_kroot,
        const GnssTime& disclosed_key_time);

    Result VerifyPendingMacks(const OsnmaDsmKroot& trusted_kroot,
        const GnssTime& now);

private:
    OsnmaDsmAssembler dsm_assembler_{};
    OsnmaDsmContentDecoder dsm_content_decoder_{};
    OsnmaTrustStore trust_store_{};
    OsnmaMackProcessor mack_processor_{};
    GalileoNavCandidateStore nav_candidate_store_{};
    OsnmaTeslaChain tesla_chain_{};
    OsnmaMacVerifier mac_verifier_{};

    std::array<PendingMack, MAX_PENDING_MACKS> pending_macks_{};
    std::map<AuthenticatedObjectKey, AuthenticatedObjectState> authenticated_objects_{};
    GalileoAuthDataFifo authenticated_nav_data_{};

    Statistics statistics_{};
};
