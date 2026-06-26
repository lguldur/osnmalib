// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "galileo_nav_candidate.h"
#include "osnma_dsm_content.h"
#include "osnma_mac_input.h"
#include "osnma_mack.h"
#include "osnma_tesla_chain.h"
#include "osnma_types.h"

class OsnmaMacVerifier
{
public:
    struct Result
    {
        AuthState state = AuthState::Unknown;
        AuthReason reason = AuthReason::None;

        /*
            Debug information filled by Verify().
            This is intentionally plain data so OsnmaEngine can print a useful
            terminal-failure line without knowing the verifier local variables.

            debug_stage:
                0 = none
                1 = MACSEQ
                2 = Tag0
                3 = Tag-Info
        */
        int32_t debug_stage = 0;
        int32_t debug_mack_prn = -1;
        int32_t debug_mack_wn = -1;
        double debug_mack_tow = -1.0;
        int32_t debug_macseq = -1;
        int32_t debug_mack_cop = -1;

        int32_t debug_tag_index = -1;
        int32_t debug_ctr = -1;
        int32_t debug_prnd = -1;
        OsnmaAdkd debug_adkd = OsnmaAdkd::Reserved;
        int32_t debug_tag_cop = -1;

        bool debug_has_nav = false;
        bool debug_has_key = false;
        bool debug_has_mac_input = false;

        struct SuccessRecord
        {
            int32_t prna = -1;
            int32_t prnd = -1;
            OsnmaAdkd adkd = OsnmaAdkd::Reserved;
            int32_t tag_index = -1;
            int32_t tag_bits = 0;
            GnssTime nav_time{};
            std::uint64_t nav_fingerprint = 0;

            /*
                Non-owning pointer to the exact candidate used to build the
                verified MAC input. OsnmaEngine consumes it synchronously,
                before the navigation candidate store is modified again.
            */
            const GalileoNavCandidate* nav_candidate = nullptr;
        };

        static constexpr int32_t MAX_SUCCESS_RECORDS = 8;

        int32_t success_count = 0;
        std::array<SuccessRecord, MAX_SUCCESS_RECORDS> success_records{};
    };

public:
    Result Verify(const OsnmaMackMessage& mack,
        const GalileoNavCandidateStore& nav_store,
        const OsnmaTeslaChain& tesla_chain,
        OsnmaMacFunction mac_function,
        std::uint8_t nmas) const;

private:
    enum class MacseqStatus
    {
        Ok = 0,
        WaitingForKey,
        InvalidFrameFormat,
        UnsupportedMessage,
        MackVerificationFailed
    };

private:
    static MacseqStatus VerifyMacseq(const OsnmaMackMessage& mack,
        const OsnmaTeslaChain& tesla_chain,
        OsnmaMacFunction mac_function);

    static void AddSuccess(Result& result,
        int32_t prna,
        int32_t prnd,
        OsnmaAdkd adkd,
        int32_t tag_index,
        int32_t tag_bits,
        const GnssTime& nav_time,
        std::uint64_t nav_fingerprint,
        const GalileoNavCandidate& nav_candidate);

    static bool BuildMacseqInput(const OsnmaMackMessage& mack,
        int32_t maclt,
        std::vector<std::uint8_t>& out);

    static void AppendGstSf32(const GnssTime& time,
        std::vector<std::uint8_t>& out);

    static AuthReason ReasonFromMacseqStatus(MacseqStatus status);

    static bool ComputeMac(OsnmaMacFunction mac_function,
        const std::uint8_t* key,
        int32_t key_size_bytes,
        const std::uint8_t* data,
        int32_t data_size_bytes,
        std::uint8_t* out,
        int32_t out_size_bytes);

    static bool ConstantTimeEqual(const std::uint8_t* a,
        const std::uint8_t* b,
        int32_t size_bytes);
};
