#pragma once

#include <array>
#include <cstdint>

#include "auth_record.h"
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
        std::array<std::int64_t, 16> dsm_id_count{};
        std::array<std::int64_t, 16> dsm_completed_id_count{};

        std::int64_t pkr_received = 0;
        std::int64_t pkr_verified = 0;
        std::int64_t pkr_failed = 0;

        std::int64_t kroot_received = 0;
        std::int64_t kroot_verified = 0;
        std::int64_t kroot_failed = 0;

        std::int64_t tesla_initialized = 0;
        std::int64_t tesla_init_failed = 0;
        std::int64_t disclosed_keys_verified = 0;
        std::int64_t disclosed_keys_failed = 0;

        std::int64_t subframes_waiting_for_kroot = 0;

        std::int64_t mack_parse_ok = 0;
        std::int64_t mack_parse_failed = 0;
        std::int64_t macks_added_pending = 0;

        std::int64_t pending_macks_overwritten = 0;
        std::int64_t pending_macks_cleaned = 0;
        std::int64_t pending_macks_verified_ok = 0;
        std::int64_t pending_macks_terminal_failed = 0;

        std::int64_t pending_verification_runs = 0;
        std::int64_t pending_macks_checked = 0;
        std::int64_t pending_waiting_for_key = 0;
        std::int64_t pending_missing_navdata = 0;

        std::int64_t auth_success = 0;

        int32_t pending_macks_current = 0;
        int32_t pending_macks_max_seen = 0;
    };

public:
    void Reset();

    bool SetMerkleRoot(const std::uint8_t* root_32_bytes);

    bool FeedNavigationPage(const GalileoInavPageParts& page,
        AuthReason& reason_out);

    Result ProcessSubframe(const OsnmaSubframe& subframe,
        NavSignalSource source,
        int32_t raw_source);

    const Statistics& GetStatistics() const;

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

    Statistics statistics_{};
};
