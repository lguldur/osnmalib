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

public:
    void Reset();

    bool SetMerkleRoot(const std::uint8_t* root_32_bytes);

    bool FeedNavigationPage(const GalileoInavPageParts& page,
        AuthReason& reason_out);

    Result ProcessSubframe(const OsnmaSubframe& subframe,
        NavSignalSource source,
        int32_t raw_source);

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
};
