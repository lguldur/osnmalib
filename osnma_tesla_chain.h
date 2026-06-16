#pragma once

#include <array>
#include <cstdint>

#include "gnss_time.h"
#include "osnma_dsm_content.h"
#include "osnma_mack.h"
#include "osnma_types.h"

class OsnmaTeslaChain
{
public:
    static constexpr int32_t MAX_STORED_KEYS = 128;
    static constexpr int32_t MAX_KEY_BYTES = 32;

public:
    void Reset();

    bool InitializeFromKroot(const OsnmaDsmKroot& kroot,
        AuthReason& reason_out);

    bool IsInitialized() const;

    int32_t GetMacLookupTable() const;

    bool VerifyAndStoreDisclosedKey(const OsnmaMackMessage& mack,
        AuthReason& reason_out);

    bool GetKeyForTag(const OsnmaMackMessage& mack,
        const OsnmaMackTagInfo& tag,
        const std::uint8_t*& key,
        int32_t& key_size_bytes) const;


    bool HasKey(int32_t key_index) const;

    const std::uint8_t* GetKey(int32_t key_index) const;

    int32_t GetKeySizeBytes(int32_t key_index) const;

private:
    struct KeyEntry
    {
        bool valid = false;
        bool verified = false;

        int32_t index = -1;
        GnssTime time{};

        int32_t size_bytes = 0;
        std::array<std::uint8_t, MAX_KEY_BYTES> key{};
    };

private:
    bool initialized_ = false;

    OsnmaHashFunction hash_function_ = OsnmaHashFunction::Reserved;

    int32_t key_size_bits_ = 0;
    int32_t key_size_bytes_ = 0;

    int32_t root_wn_ = -1;
    double root_tow_s_ = -1.0;

    int32_t mac_lookup_table_ = -1;

    std::uint64_t alpha_ = 0;

    std::array<KeyEntry, MAX_STORED_KEYS> keys_{};

private:
    int32_t FindFreeSlot() const;

    int32_t FindKeySlot(int32_t key_index) const;

    int32_t ComputeDisclosureIndex(const GnssTime& time) const;

    GnssTime ComputeTimeForIndex(int32_t key_index) const;

    int32_t ComputeKeyIndexForTag(const OsnmaMackMessage& mack,
        const OsnmaMackTagInfo& tag) const;

    int32_t GetKeyDelaySubframes(const OsnmaMackMessage& mack,
        const OsnmaMackTagInfo& tag) const;

    bool StoreVerifiedKey(int32_t key_index,
        const GnssTime& time,
        const std::uint8_t* key,
        int32_t key_size_bytes);

    bool VerifyAgainstKnownKey(int32_t candidate_index,
        const std::uint8_t* candidate_key,
        int32_t candidate_key_size_bytes) const;

    bool TransformOneStep(const std::uint8_t* input_key,
        int32_t input_key_size_bytes,
        int32_t input_key_index,
        std::uint8_t* output_key,
        int32_t output_key_capacity_bytes,
        int32_t& output_key_size_bytes) const;

    static void StoreGst32(const GnssTime& time,
        std::uint8_t out[4]);

    static void StoreAlpha48(std::uint64_t alpha,
        std::uint8_t out[6]);

    static bool ConstantTimeEqual(const std::uint8_t* a,
        const std::uint8_t* b,
        int32_t size_bytes);
};
