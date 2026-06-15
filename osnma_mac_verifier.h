#pragma once

#include <cstdint>

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
    };

public:
    Result Verify(const OsnmaMackMessage& mack,
        const GalileoNavCandidateStore& nav_store,
        const OsnmaTeslaChain& tesla_chain,
        OsnmaMacFunction mac_function,
        std::uint8_t nmas,
        const GnssTime& now) const;

private:
    static bool VerifyMacseq(const OsnmaMackMessage& mack,
        const OsnmaTeslaChain& tesla_chain,
        OsnmaMacFunction mac_function);

    static bool BuildMacseqInput(const OsnmaMackMessage& mack,
        int32_t maclt,
        std::vector<std::uint8_t>& out);

    static void AppendGstSf32(const GnssTime& time,
        std::vector<std::uint8_t>& out);

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
