#include "osnma_tesla_chain.h"

#include <cstring>

#include "osnma_crypto.h"
#include "osnma_mac_lookup.h"

static constexpr double GAL_WEEK_SECONDS = 604800.0;
static constexpr double TESLA_STEP_S = 30.0;

void OsnmaTeslaChain::Reset()
{
    initialized_ = false;

    hash_function_ = OsnmaHashFunction::Reserved;

    key_size_bits_ = 0;
    key_size_bytes_ = 0;

    root_wn_ = -1;
    root_tow_s_ = -1.0;

    mac_lookup_table_ = -1;

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

    /*
        The KROOT GST points to the following subframe boundary. The root key
        itself corresponds to KROOT GST - 30 seconds.
    */
    root_wn_ = kroot.kroot_wn;
    root_tow_s_ = static_cast<double>(kroot.kroot_towh) * 3600.0 - TESLA_STEP_S;

    while (root_tow_s_ < 0.0)
    {
        --root_wn_;
        root_tow_s_ += GAL_WEEK_SECONDS;
    }

    while (root_tow_s_ >= GAL_WEEK_SECONDS)
    {
        ++root_wn_;
        root_tow_s_ -= GAL_WEEK_SECONDS;
    }

    mac_lookup_table_ = kroot.mac_lookup_table;

    alpha_ = kroot.alpha;

    initialized_ = true;

    GnssTime root_time{};
    root_time.wn = root_wn_;
    root_time.tow = root_tow_s_;

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

    const GnssTime key_time =
        ComputeTimeForIndex(key_index);

    const bool stored =
        StoreVerifiedKey(key_index,
            key_time,
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

    const int32_t target_key_index =
        ComputeKeyIndexForTag(mack, tag);

    if (target_key_index < 0)
        return false;

    const int32_t slot =
        FindKeySlot(target_key_index);

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

int32_t OsnmaTeslaChain::ComputeDisclosureIndex(const GnssTime& time) const
{
    if (!initialized_)
        return -1;

    GnssTime root_time{};
    root_time.wn = root_wn_;
    root_time.tow = root_tow_s_;

    const double dt_s = DiffSeconds(time, root_time);

    if (dt_s < 0.0)
        return -1;

    return static_cast<int32_t>(dt_s / TESLA_STEP_S);
}

GnssTime OsnmaTeslaChain::ComputeTimeForIndex(int32_t key_index) const
{
    GnssTime time{};

    time.wn = root_wn_;
    time.tow = root_tow_s_;

    if (key_index < 0)
        return time;

    time.tow += static_cast<double>(key_index) * TESLA_STEP_S;

    while (time.tow >= GAL_WEEK_SECONDS)
    {
        ++time.wn;
        time.tow -= GAL_WEEK_SECONDS;
    }

    while (time.tow < 0.0)
    {
        --time.wn;
        time.tow += GAL_WEEK_SECONDS;
    }

    return time;
}

int32_t OsnmaTeslaChain::ComputeKeyIndexForTag(const OsnmaMackMessage& mack,
    const OsnmaMackTagInfo& tag) const
{
    const int32_t tag_index =
        ComputeDisclosureIndex(mack.subframe_epoch);

    if (tag_index < 0)
        return -1;

    const int32_t delay_subframes =
        GetKeyDelaySubframes(mack, tag);

    if (delay_subframes <= 0)
        return -1;

    /*
        The tag is transmitted first; the corresponding key is disclosed later.
    */
    const int32_t target =
        tag_index + delay_subframes;

    return target;
}

int32_t OsnmaTeslaChain::GetKeyDelaySubframes(const OsnmaMackMessage& mack,
    const OsnmaMackTagInfo& tag) const
{
    if (mac_lookup_table_ < 0)
        return -1;

    if (!OsnmaMacLookupTable::IsTagConsistent(mac_lookup_table_,
        mack.subframe_epoch,
        mack.prn,
        tag))
    {
        return -1;
    }

    return OsnmaMacLookupTable::GetNominalDelaySubframes(mac_lookup_table_,
        mack.subframe_epoch,
        tag);
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
                step,
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
    int32_t input_key_index,
    std::uint8_t* output_key,
    int32_t output_key_capacity_bytes,
    int32_t& output_key_size_bytes) const
{
    output_key_size_bytes = 0;

    if (input_key == nullptr || output_key == nullptr)
        return false;

    if (input_key_size_bytes <= 0)
        return false;

    if (input_key_index <= 0)
        return false;

    if (output_key_capacity_bytes < key_size_bytes_)
        return false;

    std::array<std::uint8_t, MAX_KEY_BYTES + 4 + 6> hash_input{};
    int32_t hash_input_size = 0;

    std::memcpy(hash_input.data(),
        input_key,
        static_cast<size_t>(input_key_size_bytes));

    hash_input_size += input_key_size_bytes;

    const GnssTime previous_time =
        ComputeTimeForIndex(input_key_index - 1);

    std::uint8_t gst_bytes[4]{};
    StoreGst32(previous_time, gst_bytes);

    std::memcpy(hash_input.data() + hash_input_size,
        gst_bytes,
        4);

    hash_input_size += 4;

    std::uint8_t alpha_bytes[6]{};
    StoreAlpha48(alpha_, alpha_bytes);

    std::memcpy(hash_input.data() + hash_input_size,
        alpha_bytes,
        6);

    hash_input_size += 6;

    std::array<std::uint8_t, 64> digest{};

    bool ok = false;

    if (hash_function_ == OsnmaHashFunction::Sha256)
    {
        ok = OsnmaSha256(hash_input.data(),
            hash_input_size,
            digest.data());
    }
    else if (hash_function_ == OsnmaHashFunction::Sha3_256)
    {
        ok = OsnmaSha3_256(hash_input.data(),
            hash_input_size,
            digest.data());
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

void OsnmaTeslaChain::StoreGst32(const GnssTime& time,
    std::uint8_t out[4])
{
    const std::uint32_t wn =
        static_cast<std::uint32_t>(time.wn) & 0x0FFFu;

    const std::uint32_t tow =
        static_cast<std::uint32_t>(time.tow) & 0x000FFFFFu;

    const std::uint32_t value =
        (wn << 20) | tow;

    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

void OsnmaTeslaChain::StoreAlpha48(std::uint64_t alpha,
    std::uint8_t out[6])
{
    const std::uint64_t v =
        alpha & 0x0000FFFFFFFFFFFFull;

    out[0] = static_cast<std::uint8_t>((v >> 40) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((v >> 32) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
    out[3] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    out[4] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    out[5] = static_cast<std::uint8_t>(v & 0xFFu);
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
