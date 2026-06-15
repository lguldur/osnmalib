#include "osnma_mac_verifier.h"

#include <array>
#include <vector>

#include "osnma_bit_utils.h"
#include "osnma_crypto.h"
#include "osnma_mac_lookup.h"

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

    /*
        Before validating individual tags, validate MACSEQ.

        MACSEQ authenticates:
            PRNA || GST_SF || tag_info of FLX slots

        If the future TESLA key is not available yet, this is not a MAC
        failure. The pending MACK must remain queued.
    */
    const MacseqStatus macseq_status =
        VerifyMacseq(mack,
            tesla_chain,
            mac_function);

    if (macseq_status != MacseqStatus::Ok)
    {
        result.reason =
            ReasonFromMacseqStatus(macseq_status);

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

OsnmaMacVerifier::MacseqStatus
OsnmaMacVerifier::VerifyMacseq(const OsnmaMackMessage& mack,
    const OsnmaTeslaChain& tesla_chain,
    OsnmaMacFunction mac_function)
{
    if (!mack.valid_layout)
        return MacseqStatus::InvalidFrameFormat;

    if (mack.prn <= 0 || mack.prn > 255)
        return MacseqStatus::InvalidFrameFormat;

    const int32_t maclt =
        tesla_chain.GetMacLookupTable();

    if (maclt < 0)
        return MacseqStatus::WaitingForKey;

    /*
        MACSEQ uses the next-subframe TESLA key. This is the same key selected
        for Tag0 / ADKD=0 self-authentication.
    */
    OsnmaMackTagInfo tag0_info{};
    tag0_info.index = 0;
    tag0_info.prnd = mack.prn;
    tag0_info.adkd = OsnmaAdkd::InavCed;
    tag0_info.cop = mack.cop;
    tag0_info.tag_size_bits = mack.tag_size_bits;
    tag0_info.tag_size_bytes = mack.tag_size_bytes;
    tag0_info.valid_info = true;

    const std::uint8_t* key = nullptr;
    int32_t key_size_bytes = 0;

    if (!tesla_chain.GetKeyForTag(mack,
        tag0_info,
        key,
        key_size_bytes))
    {
        return MacseqStatus::WaitingForKey;
    }

    std::vector<std::uint8_t> macseq_input;

    if (!BuildMacseqInput(mack,
        maclt,
        macseq_input))
    {
        return MacseqStatus::InvalidFrameFormat;
    }

    std::array<std::uint8_t, OsnmaMackTagInfo::MAX_TAG_BYTES> computed{};

    const bool computed_ok =
        ComputeMac(mac_function,
            key,
            key_size_bytes,
            macseq_input.data(),
            static_cast<int32_t>(macseq_input.size()),
            computed.data(),
            2);

    if (!computed_ok)
        return MacseqStatus::UnsupportedMessage;

    /*
        MACSEQ is the first 12 bits of the MAC output.
    */
    const std::uint8_t expected0 =
        static_cast<std::uint8_t>((mack.macseq >> 4) & 0xFF);

    const std::uint8_t expected1_high =
        static_cast<std::uint8_t>((mack.macseq & 0x0F) << 4);

    if (computed[0] != expected0)
        return MacseqStatus::MackVerificationFailed;

    if ((computed[1] & 0xF0u) != expected1_high)
        return MacseqStatus::MackVerificationFailed;

    return MacseqStatus::Ok;
}

bool OsnmaMacVerifier::BuildMacseqInput(const OsnmaMackMessage& mack,
    int32_t maclt,
    std::vector<std::uint8_t>& out)
{
    out.clear();

    if (!mack.valid_layout)
        return false;

    if (mack.prn <= 0 || mack.prn > 255)
        return false;

    if (!IsTimeValid(mack.subframe_epoch))
        return false;

    out.reserve(5 + 2 * OsnmaMackMessage::MAX_TAGS);

    out.push_back(static_cast<std::uint8_t>(mack.prn));

    AppendGstSf32(mack.subframe_epoch,
        out);

    /*
        For each FLX slot selected by MACLT/GST row, append the corresponding
        raw 16-bit Tag-Info field.

        Important: use the raw bits from the MACK message, not the decoded
        ADKD enum, because FLX can legally contain values that are not fixed
        by the MACLT table.
    */
    for (int32_t tag_number = 1;
        tag_number < mack.total_tag_count;
        ++tag_number)
    {
        OsnmaMacLookupSlot slot{};

        if (!OsnmaMacLookupTable::GetExpectedSlot(maclt,
            mack.subframe_epoch,
            tag_number,
            slot))
        {
            return false;
        }

        if (slot.target != OsnmaMacTagAuthTarget::Flexible)
            continue;

        const int32_t tag_and_info_bits =
            mack.tag_size_bits + 16;

        const int32_t tag_info_start =
            tag_number * tag_and_info_bits + mack.tag_size_bits;

        if ((tag_info_start + 16) > OsnmaMackMessage::MACK_BITS)
            return false;

        std::uint8_t tag_info_bytes[2]{};

        CopyBitsMsb0(mack.raw.data(),
            tag_info_start,
            16,
            tag_info_bytes,
            2);

        out.push_back(tag_info_bytes[0]);
        out.push_back(tag_info_bytes[1]);
    }

    return !out.empty();
}

void OsnmaMacVerifier::AppendGstSf32(const GnssTime& time,
    std::vector<std::uint8_t>& out)
{
    const std::uint32_t wn =
        static_cast<std::uint32_t>(time.wn) & 0x0FFFu;

    const std::uint32_t tow =
        static_cast<std::uint32_t>(time.tow) & 0x000FFFFFu;

    const std::uint32_t value =
        (wn << 20) | tow;

    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

AuthReason
OsnmaMacVerifier::ReasonFromMacseqStatus(MacseqStatus status)
{
    switch (status)
    {
    case MacseqStatus::Ok:
        return AuthReason::None;

    case MacseqStatus::WaitingForKey:
        return AuthReason::WaitingForKey;

    case MacseqStatus::InvalidFrameFormat:
        return AuthReason::InvalidFrameFormat;

    case MacseqStatus::UnsupportedMessage:
        return AuthReason::UnsupportedMessage;

    case MacseqStatus::MackVerificationFailed:
        return AuthReason::MackVerificationFailed;

    default:
        return AuthReason::MackVerificationFailed;
    }
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
