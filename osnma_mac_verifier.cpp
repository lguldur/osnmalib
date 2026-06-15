#include "osnma_mac_verifier.h"

#include <array>
#include <vector>

#include "osnma_crypto.h"

OsnmaMacVerifier::Result
OsnmaMacVerifier::Verify(const OsnmaMackMessage& mack,
    const GalileoNavCandidateStore& nav_store,
    const OsnmaTeslaChain& tesla_chain,
    OsnmaMacFunction mac_function,
    std::uint8_t nmas,
    const GnssTime& now) const
{
    Result result{};
    result.state = AuthState::Unknown;
    result.reason = AuthReason::MissingNavData;

    if (!mack.valid_layout)
    {
        result.reason = AuthReason::InvalidFrameFormat;
        return result;
    }

    bool saw_candidate = false;
    bool saw_key = false;
    bool saw_mac_input = false;

    /*
        First verify Tag0.

        Tag0 authenticates ADKD=0 CED/status for the transmitting satellite:
            PRND = PRNA = mack.prn
            CTR  = 1
    */
    {
        const GalileoNavCandidate* tag0_candidate =
            nav_store.FindForAdkd(mack.prn,
                OsnmaAdkd::InavCed,
                now);

        if (tag0_candidate != nullptr)
        {
            saw_candidate = true;

            const std::uint8_t* key = nullptr;
            int32_t key_size_bytes = 0;

            /*
                Tag0 uses the same key selection rule as normal ADKD=0 self
                tags. We create a local tag descriptor for key selection only.
            */
            OsnmaMackTagInfo tag0_info{};
            tag0_info.index = 0;
            tag0_info.prnd = mack.prn;
            tag0_info.adkd = OsnmaAdkd::InavCed;
            tag0_info.cop = mack.cop;
            tag0_info.tag_size_bits = mack.tag_size_bits;
            tag0_info.tag_size_bytes = mack.tag_size_bytes;
            tag0_info.valid_info = true;

            if (tesla_chain.GetKeyForTag(mack,
                tag0_info,
                key,
                key_size_bytes))
            {
                saw_key = true;

                std::vector<std::uint8_t> mac_input;

                if (OsnmaMacInputBuilder::BuildTag0Message(mack,
                    *tag0_candidate,
                    nmas,
                    mac_input))
                {
                    saw_mac_input = true;

                    std::array<std::uint8_t, OsnmaMackTagInfo::MAX_TAG_BYTES> computed{};

                    const bool computed_ok =
                        ComputeMac(mac_function,
                            key,
                            key_size_bytes,
                            mac_input.data(),
                            static_cast<int32_t>(mac_input.size()),
                            computed.data(),
                            mack.tag_size_bytes);

                    if (!computed_ok)
                    {
                        result.reason = AuthReason::UnsupportedMessage;
                        return result;
                    }

                    if (ConstantTimeEqual(computed.data(),
                        mack.tag0.data(),
                        mack.tag_size_bytes))
                    {
                        result.state = AuthState::Yes;
                        result.reason = AuthReason::None;
                        return result;
                    }
                }
            }
        }
    }

    /*
        Then verify Tag-Info entries.
    */
    for (int32_t i = 0; i < mack.tag_info_count; ++i)
    {
        const OsnmaMackTagInfo& tag = mack.tag_info[i];

        if (!tag.valid_info)
            continue;

        const GalileoNavCandidate* candidate =
            nav_store.FindForAdkd(tag.prnd,
                tag.adkd,
                now);

        if (candidate == nullptr)
            continue;

        saw_candidate = true;

        const std::uint8_t* key = nullptr;
        int32_t key_size_bytes = 0;

        if (!tesla_chain.GetKeyForTag(mack,
            tag,
            key,
            key_size_bytes))
        {
            continue;
        }

        saw_key = true;

        std::vector<std::uint8_t> mac_input;

        if (!OsnmaMacInputBuilder::BuildTagMessage(mack,
            tag,
            *candidate,
            nmas,
            mac_input))
        {
            continue;
        }

        saw_mac_input = true;

        std::array<std::uint8_t, OsnmaMackTagInfo::MAX_TAG_BYTES> computed{};

        const bool computed_ok =
            ComputeMac(mac_function,
                key,
                key_size_bytes,
                mac_input.data(),
                static_cast<int32_t>(mac_input.size()),
                computed.data(),
                tag.tag_size_bytes);

        if (!computed_ok)
        {
            result.reason = AuthReason::UnsupportedMessage;
            return result;
        }

        if (ConstantTimeEqual(computed.data(),
            tag.tag.data(),
            tag.tag_size_bytes))
        {
            result.state = AuthState::Yes;
            result.reason = AuthReason::None;
            return result;
        }
    }

    result.state = AuthState::Unknown;

    if (!saw_candidate)
        result.reason = AuthReason::MissingNavData;
    else if (!saw_key)
        result.reason = AuthReason::WaitingForKey;
    else if (!saw_mac_input)
        result.reason = AuthReason::UnsupportedMessage;
    else
        result.reason = AuthReason::MackVerificationFailed;

    return result;
}

bool OsnmaMacVerifier::ComputeMac(OsnmaMacFunction mac_function,
    const std::uint8_t* key,
    int32_t key_size_bytes,
    const std::uint8_t* data,
    int32_t data_size_bytes,
    std::uint8_t* out,
    int32_t out_size_bytes)
{
    if (key == nullptr || data == nullptr || out == nullptr)
        return false;

    if (key_size_bytes <= 0 || data_size_bytes <= 0 || out_size_bytes <= 0)
        return false;

    if (out_size_bytes > OsnmaMackTagInfo::MAX_TAG_BYTES)
        return false;

    if (mac_function == OsnmaMacFunction::HmacSha256)
    {
        return OsnmaHmacSha256(key,
            key_size_bytes,
            data,
            data_size_bytes,
            out,
            out_size_bytes);
    }

    if (mac_function == OsnmaMacFunction::CmacAes)
    {
        std::array<std::uint8_t, 16> full_cmac{};

        if (!OsnmaAesCmac(key,
            key_size_bytes,
            data,
            data_size_bytes,
            full_cmac.data()))
        {
            return false;
        }

        for (int32_t i = 0; i < out_size_bytes; ++i)
            out[i] = full_cmac[i];

        return true;
    }

    return false;
}

bool OsnmaMacVerifier::ConstantTimeEqual(const std::uint8_t* a,
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
