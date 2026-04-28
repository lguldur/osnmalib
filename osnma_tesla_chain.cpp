#include "osnma_tesla_chain.h"

#include <cstring>

#include "osnma_crypto.h"

void OsnmaTeslaChain::Reset()
{
    initialized_ = false;

    hash_function_ = OsnmaHashFunction::Reserved;

    key_size_bits_ = 0;
    key_size_bytes_ = 0;

    root_wn_ = -1;
    root_towh_ = -1;

    alpha_ = 0;

    for (auto& k : keys_)
        k = KeyEntry{};
}

bool OsnmaTeslaChain::InitializeFromKroot(const OsnmaDsmKroot& kroot,
    AuthReason& reason_out)
{
    Reset();

    reason_out = AuthReason::None;

    if (!kroot.valid_layout)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (kroot.kroot_size_bytes <= 0 ||
        kroot.kroot_size_bytes > MAX_KEY_BYTES)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (kroot.key_size_bits <= 0 ||
        (kroot.key_size_bits % 8) != 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t key_size_bytes = kroot.key_size_bits / 8;

    if (key_size_bytes <= 0 || key_size_bytes > MAX_KEY_BYTES)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (kroot.kroot_size_bytes != key_size_bytes)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (kroot.hash_function != OsnmaHashFunction::Sha256 &&
        kroot.hash_function != OsnmaHashFunction::Sha3_256)
    {
        reason_out = AuthReason::UnsupportedMessage;
        return false;
    }

    if (kroot.kroot_wn < 0 || kroot.kroot_towh < 0)
    {
        reason_out = AuthReason::InvalidTime;
        return false;
    }

    hash_function_ = kroot.hash_function;

    key_size_bits_ = kroot.key_size_bits;
    key_size_bytes_ = key_size_bytes;

    root_wn_ = kroot.kroot_wn;
    root_towh_ = kroot.kroot_towh;

    alpha_ = kroot.alpha;

    initialized_ = true;

    GnssTime root_time{};
    root_time.wn = root_wn_;
    root_time.tow = static_cast<double>(root_towh_) * 3600.0;

    return StoreVerifiedKey(0,
        root_time,
        kroot.kroot.data(),
        kroot.kroot_size_bytes);
}

bool OsnmaTeslaChain::IsInitialized() const
{
    return initialized_;
}

bool OsnmaTeslaChain::VerifyAndStoreDisclosedKey(const OsnmaMackMessage& mack,
    AuthReason& reason_out)
{
    reason_out = AuthReason::None;

    if (!initialized_)
    {
        reason_out = AuthReason::WaitingForKey;
        return false;
    }

    if (!mack.valid_layout)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (!IsTimeValid(mack.subframe_epoch))
    {
        reason_out = AuthReason::InvalidTime;
        return false;
    }

    if (mack.key_size_bytes != key_size_bytes_)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    const int32_t key_index =
        ComputeDisclosureIndex(mack.subframe_epoch);

    if (key_index <= 0)
    {
        reason_out = AuthReason::InvalidTime;
        return false;
    }

    const int32_t existing_slot = FindKeySlot(key_index);

    if (existing_slot >= 0)
    {
        const KeyEntry& existing = keys_[existing_slot];

        if (ConstantTimeEqual(existing.key.data(),
            mack.disclosed_key.data(),
            key_size_bytes_))
        {
            reason_out = AuthReason::None;
            return true;
        }

        reason_out = AuthReason::TeslaChainVerificationFailed;
        return false;
    }

    const bool verified =
        VerifyAgainstKnownKey(key_index,
            mack.disclosed_key.data(),
            key_size_bytes_);

    if (!verified)
    {
        reason_out = AuthReason::TeslaChainVerificationFailed;
        return false;
    }

    const bool stored =
        StoreVerifiedKey(key_index,
            mack.subframe_epoch,
            mack.disclosed_key.data(),
            key_size_bytes_);

    if (!stored)
    {
        reason_out = AuthReason::BufferOverflow;
        return false;
    }

    reason_out = AuthReason::None;
    return true;
}

bool OsnmaTeslaChain::GetKeyForTag(const OsnmaMackMessage& mack,
    const OsnmaMackTagInfo& tag,
    const std::uint8_t*& key,
    int32_t& key_size_bytes) const
{
    key = nullptr;
    key_size_bytes = 0;

    if (!initialized_)
        return false;

    if (!mack.valid_layout || !tag.valid_info)
        return false;

    const int32_t disclosure_index =
        ComputeDisclosureIndex(mack.subframe_epoch);

    if (disclosure_index < 0)
        return false;

    /*
        Current simplified key selection.

        For now, use the verified disclosed key associated with this MACK
        subframe, or the closest previous verified key if exact index is not
        present.

        The final OSNMA version must refine this with the exact TESLA key
        delay / tag-to-key mapping from the ICD.
    */

    int32_t slot = FindKeySlot(disclosure_index);

    if (slot < 0)
        slot = FindClosestKeySlot(disclosure_index);

    if (slot < 0)
        return false;

    const KeyEntry& entry = keys_[slot];

    if (!entry.valid || !entry.verified)
        return false;

    key = entry.key.data();
    key_size_bytes = entry.size_bytes;

    return true;
}

bool OsnmaTeslaChain::HasKey(int32_t key_index) const
{
    return FindKeySlot(key_index) >= 0;
}

const std::uint8_t* OsnmaTeslaChain::GetKey(int32_t key_index) const
{
    const int32_t slot = FindKeySlot(key_index);

    if (slot < 0)
        return nullptr;

    return keys_[slot].key.data();
}

int32_t OsnmaTeslaChain::GetKeySizeBytes(int32_t key_index) const
{
    const int32_t slot = FindKeySlot(key_index);

    if (slot < 0)
        return 0;

    return keys_[slot].size_bytes;
}

int32_t OsnmaTeslaChain::FindFreeSlot() const
{
    for (int32_t i = 0; i < MAX_STORED_KEYS; ++i)
    {
        if (!keys_[i].valid)
            return i;
    }

    return -1;
}

int32_t OsnmaTeslaChain::FindKeySlot(int32_t key_index) const
{
    for (int32_t i = 0; i < MAX_STORED_KEYS; ++i)
    {
        if (keys_[i].valid &&
            keys_[i].verified &&
            keys_[i].index == key_index)
        {
            return i;
        }
    }

    return -1;
}

int32_t OsnmaTeslaChain::FindClosestKeySlot(int32_t key_index) const
{
    int32_t best = -1;

    for (int32_t i = 0; i < MAX_STORED_KEYS; ++i)
    {
        if (!keys_[i].valid || !keys_[i].verified)
            continue;

        if (keys_[i].index > key_index)
            continue;

        if (best < 0 || keys_[i].index > keys_[best].index)
            best = i;
    }

    return best;
}

int32_t OsnmaTeslaChain::ComputeDisclosureIndex(const GnssTime& time) const
{
    if (!initialized_)
        return -1;

    GnssTime root_time{};
    root_time.wn = root_wn_;
    root_time.tow = static_cast<double>(root_towh_) * 3600.0;

    const double dt_s = DiffSeconds(time, root_time);

    if (dt_s < 0.0)
        return -1;

    static constexpr double TESLA_STEP_S = 30.0;

    return static_cast<int32_t>(dt_s / TESLA_STEP_S);
}

bool OsnmaTeslaChain::StoreVerifiedKey(int32_t key_index,
    const GnssTime& time,
    const std::uint8_t* key,
    int32_t key_size_bytes)
{
    if (key == nullptr)
        return false;

    if (key_index < 0)
        return false;

    if (key_size_bytes <= 0 || key_size_bytes > MAX_KEY_BYTES)
        return false;

    const int32_t existing_slot = FindKeySlot(key_index);

    if (existing_slot >= 0)
    {
        KeyEntry& existing = keys_[existing_slot];

        return ConstantTimeEqual(existing.key.data(),
            key,
            key_size_bytes);
    }

    int32_t slot = FindFreeSlot();

    if (slot < 0)
    {
        int32_t oldest = -1;

        for (int32_t i = 0; i < MAX_STORED_KEYS; ++i)
        {
            if (!keys_[i].valid)
                continue;

            if (oldest < 0 || keys_[i].index < keys_[oldest].index)
                oldest = i;
        }

        slot = oldest;
    }

    if (slot < 0)
        return false;

    KeyEntry& entry = keys_[slot];

    entry = KeyEntry{};

    entry.valid = true;
    entry.verified = true;
    entry.index = key_index;
    entry.time = time;
    entry.size_bytes = key_size_bytes;

    std::memcpy(entry.key.data(),
        key,
        static_cast<size_t>(key_size_bytes));

    return true;
}

bool OsnmaTeslaChain::VerifyAgainstKnownKey(int32_t candidate_index,
    const std::uint8_t* candidate_key,
    int32_t candidate_key_size_bytes) const
{
    if (!initialized_)
        return false;

    if (candidate_key == nullptr)
        return false;

    if (candidate_index <= 0)
        return false;

    if (candidate_key_size_bytes != key_size_bytes_)
        return false;

    for (const KeyEntry& known : keys_)
    {
        if (!known.valid || !known.verified)
            continue;

        if (known.index < 0)
            continue;

        if (known.index >= candidate_index)
            continue;

        std::array<std::uint8_t, MAX_KEY_BYTES> current{};
        std::memcpy(current.data(),
            candidate_key,
            static_cast<size_t>(candidate_key_size_bytes));

        int32_t current_size = candidate_key_size_bytes;

        bool transform_ok = true;

        for (int32_t step = candidate_index;
            step > known.index;
            --step)
        {
            std::array<std::uint8_t, MAX_KEY_BYTES> next{};
            int32_t next_size = 0;

            if (!TransformOneStep(current.data(),
                current_size,
                next.data(),
                static_cast<int32_t>(next.size()),
                next_size))
            {
                transform_ok = false;
                break;
            }

            current = next;
            current_size = next_size;
        }

        if (!transform_ok)
            continue;

        if (current_size != known.size_bytes)
            continue;

        if (ConstantTimeEqual(current.data(),
            known.key.data(),
            known.size_bytes))
        {
            return true;
        }
    }

    return false;
}

bool OsnmaTeslaChain::TransformOneStep(const std::uint8_t* input_key,
    int32_t input_key_size_bytes,
    std::uint8_t* output_key,
    int32_t output_key_capacity_bytes,
    int32_t& output_key_size_bytes) const
{
    output_key_size_bytes = 0;

    if (input_key == nullptr || output_key == nullptr)
        return false;

    if (input_key_size_bytes <= 0)
        return false;

    if (output_key_capacity_bytes < key_size_bytes_)
        return false;

    std::array<std::uint8_t, 64> digest{};

    bool ok = false;

    if (hash_function_ == OsnmaHashFunction::Sha256)
    {
        ok = OsnmaSha256(input_key,
            input_key_size_bytes,
            digest.data());
    }
    else if (hash_function_ == OsnmaHashFunction::Sha3_256)
    {
        return false;
    }
    else
    {
        return false;
    }

    if (!ok)
        return false;

    std::memcpy(output_key,
        digest.data(),
        static_cast<size_t>(key_size_bytes_));

    output_key_size_bytes = key_size_bytes_;
    return true;
}

bool OsnmaTeslaChain::ConstantTimeEqual(const std::uint8_t* a,
    const std::uint8_t* b,
    int32_t size_bytes)
{
    if (a == nullptr || b == nullptr)
        return false;

    if (size_bytes <= 0)
        return false;

    std::uint8_t diff = 0;

    for (int32_t i = 0; i < size_bytes; ++i)
        diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);

    return diff == 0;
}
