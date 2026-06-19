#include "osnma_mac_verifier.h"

#include <array>
#include <cstdio>
#include <vector>
#include <cstdint>

#include "osnma_bit_utils.h"
#include "osnma_crypto.h"
#include "osnma_mac_lookup.h"

#ifndef OSNMA_VERBOSE_NAVDATA
#define OSNMA_VERBOSE_NAVDATA 0
#endif

namespace
{
    GnssTime AddSecondsNormalized(const GnssTime& time,
        double seconds)
    {
        GnssTime out = time;

        out.tow += seconds;

        while (out.tow < 0.0)
        {
            --out.wn;
            out.tow += 604800.0;
        }

        while (out.tow >= 604800.0)
        {
            ++out.wn;
            out.tow -= 604800.0;
        }

        return out;
    }

    GnssTime NavDataLookupTime(const GnssTime& mack_time,
        OsnmaAdkd adkd)
    {
        if (adkd == OsnmaAdkd::InavCed ||
            adkd == OsnmaAdkd::InavTiming ||
            adkd == OsnmaAdkd::SlowMac)
        {
            return AddSecondsNormalized(mack_time,
                -30.0);
        }

        return mack_time;
    }

    void PrintHexPrefix(const char* label,
        const std::uint8_t* data,
        int32_t size_bytes,
        int32_t max_bytes)
    {
        printf("%s", label);

        if (data == nullptr || size_bytes <= 0 || max_bytes <= 0)
        {
            printf("-");
            return;
        }

        const int32_t n =
            (size_bytes < max_bytes) ? size_bytes : max_bytes;

        for (int32_t i = 0; i < n; ++i)
            printf("%02X", data[i]);

        if (size_bytes > n)
            printf("...");
    }

    void PrintHexFull(const char* label,
        const std::uint8_t* data,
        int32_t size_bytes)
    {
        PrintHexPrefix(label,
            data,
            size_bytes,
            size_bytes);
    }

    bool IsGalileoPrn(int32_t prn)
    {
        return prn >= 1 && prn <= 36;
    }

    std::uint64_t Fnv1a64(const std::uint8_t* data,
        int32_t size_bytes)
    {
        static constexpr std::uint64_t FNV_OFFSET =
            14695981039346656037ull;
        static constexpr std::uint64_t FNV_PRIME =
            1099511628211ull;

        std::uint64_t h = FNV_OFFSET;

        if (data == nullptr || size_bytes <= 0)
            return h;

        for (int32_t i = 0; i < size_bytes; ++i)
        {
            h ^= static_cast<std::uint64_t>(data[i]);
            h *= FNV_PRIME;
        }

        return h;
    }

    std::uint64_t NavFingerprintFromMacInput(const std::vector<std::uint8_t>& mac_input,
        bool tag0)
    {
        /*
            Daniel logs new authenticated navigation objects, not every
            authenticated tag/GST. The navigation object identity is therefore
            based on the authenticated NMAS+navdata payload, excluding the
            tag-specific PRN/GST/CTR prefix:

              Tag0:       PRNA || GST || CTR || NMAS || navdata
                           ^ hash from byte 6

              Normal tag: PRND || PRNA || GST || CTR || NMAS || navdata
                           ^ hash from byte 7
        */
        const int32_t offset = tag0 ? 6 : 7;

        if (static_cast<int32_t>(mac_input.size()) <= offset)
            return Fnv1a64(nullptr, 0);

        return Fnv1a64(mac_input.data() + offset,
            static_cast<int32_t>(mac_input.size()) - offset);
    }

    bool MakeEffectiveMacltTag(const OsnmaMackMessage& mack,
        int32_t maclt,
        const OsnmaMackTagInfo& raw_tag,
        OsnmaMackTagInfo& effective_tag,
        OsnmaMacLookupSlot& expected_slot)
    {
        effective_tag = raw_tag;
        expected_slot = OsnmaMacLookupSlot{};

        if (!mack.valid_layout)
            return false;

        if (raw_tag.index <= 0)
            return false;

        if (!OsnmaMacLookupTable::GetExpectedSlot(maclt,
            mack.subframe_epoch,
            raw_tag.index,
            expected_slot))
        {
            return false;
        }

        if (expected_slot.target == OsnmaMacTagAuthTarget::Flexible)
        {
            if (!raw_tag.valid_info)
                return false;

            if (raw_tag.adkd == OsnmaAdkd::Reserved)
                return false;

            if (!IsGalileoPrn(raw_tag.prnd))
                return false;

            return true;
        }

        /*
            Fixed MACLT slots define the ADKD. Do not trust the raw ADKD
            nibble carried in the Tag-Info field for these slots.

            For self-authentication slots, the authenticated satellite is the
            transmitting PRNA. For external slots, the PRND is still taken from
            the Tag-Info field.
        */
        effective_tag.adkd = expected_slot.adkd;

        if (expected_slot.target == OsnmaMacTagAuthTarget::Self)
        {
            if (!IsGalileoPrn(mack.prn))
                return false;

            effective_tag.prnd = mack.prn;
            return true;
        }

        if (expected_slot.target == OsnmaMacTagAuthTarget::External)
        {
            if (!IsGalileoPrn(raw_tag.prnd))
                return false;

            if (raw_tag.prnd == mack.prn)
                return false;

            effective_tag.prnd = raw_tag.prnd;
            return true;
        }

        return false;
    }
}

void OsnmaMacVerifier::AddSuccess(Result& result,
    int32_t prna,
    int32_t prnd,
    OsnmaAdkd adkd,
    int32_t tag_index,
    int32_t tag_bits,
    const GnssTime& nav_time,
    std::uint64_t nav_fingerprint,
    const GalileoNavCandidate& nav_candidate)
{
    if (result.success_count < 0 ||
        result.success_count >= Result::MAX_SUCCESS_RECORDS)
    {
        return;
    }

    Result::SuccessRecord& record =
        result.success_records[result.success_count];

    record.prna = prna;
    record.prnd = prnd;
    record.adkd = adkd;
    record.tag_index = tag_index;
    record.tag_bits = tag_bits;
    record.nav_time = nav_time;
    record.nav_fingerprint = nav_fingerprint;
    record.nav_candidate = &nav_candidate;

    ++result.success_count;
}

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

    result.debug_mack_prn = mack.prn;
    result.debug_mack_wn = mack.subframe_epoch.wn;
    result.debug_mack_tow = mack.subframe_epoch.tow;
    result.debug_macseq = mack.macseq;
    result.debug_mack_cop = mack.cop;

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
        result.debug_stage = 1;
        result.debug_tag_index = -1;
        result.debug_ctr = -1;
        result.debug_prnd = mack.prn;
        result.debug_adkd = OsnmaAdkd::InavCed;
        result.debug_tag_cop = mack.cop;

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
        result.debug_stage = 2;
        result.debug_tag_index = 0;
        result.debug_ctr = 1;
        result.debug_prnd = mack.prn;
        result.debug_adkd = OsnmaAdkd::InavCed;
        result.debug_tag_cop = mack.cop;
        result.debug_has_nav = false;
        result.debug_has_key = false;
        result.debug_has_mac_input = false;

        const GnssTime tag0_nav_time =
            NavDataLookupTime(mack.subframe_epoch,
                OsnmaAdkd::InavCed);

        const GalileoNavCandidate* tag0_candidate =
            nav_store.FindForAdkd(mack.prn,
                OsnmaAdkd::InavCed,
                tag0_nav_time,
                mack.cop);

        result.debug_has_nav = (tag0_candidate != nullptr);

        if (tag0_candidate == nullptr)
        {
#if OSNMA_VERBOSE_NAVDATA
            static int32_t tag0_missing_nav_debug_count = 0;

            if (tag0_missing_nav_debug_count < 40)
            {
                printf("NAVDATA lookup failed: stage=2 prna=%d prnd=%d adkd=%d ctr=%d tag_index=%d mack_wn=%d mack_tow=%.0f requested_wn=%d requested_tow=%.0f\n",
                    mack.prn,
                    mack.prn,
                    static_cast<int32_t>(OsnmaAdkd::InavCed),
                    1,
                    0,
                    mack.subframe_epoch.wn,
                    mack.subframe_epoch.tow,
                    tag0_nav_time.wn,
                    tag0_nav_time.tow);

                ++tag0_missing_nav_debug_count;
            }
#endif
        }

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
                result.debug_has_key = true;

                std::vector<std::uint8_t> mac_input;

                if (OsnmaMacInputBuilder::BuildTag0Message(mack,
                    *tag0_candidate,
                    nmas,
                    mac_input))
                {
                    saw_mac_input = true;
                    result.debug_has_mac_input = true;

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
                        AddSuccess(result,
                            mack.prn,
                            mack.prn,
                            OsnmaAdkd::InavCed,
                            0,
                            mack.tag_size_bits,
                            tag0_nav_time,
                            NavFingerprintFromMacInput(mac_input, true),
                            *tag0_candidate);
                    }


                }
            }
        }
    }

    /*
        Then verify Tag-Info entries.

        For fixed MACLT slots, build an effective tag descriptor first. The
        fixed slot defines ADKD, and self-authentication slots define PRND=PRNA.
        Only FLX slots use the received ADKD from Tag-Info.
    */
    const int32_t maclt =
        tesla_chain.GetMacLookupTable();

    for (int32_t i = 0; i < mack.tag_info_count; ++i)
    {
        const OsnmaMackTagInfo& raw_tag = mack.tag_info[i];

        OsnmaMackTagInfo tag{};
        OsnmaMacLookupSlot expected_slot{};

        if (!MakeEffectiveMacltTag(mack,
            maclt,
            raw_tag,
            tag,
            expected_slot))
        {
            continue;
        }

        result.debug_stage = 3;
        result.debug_tag_index = tag.index;
        result.debug_ctr = tag.index + 1;
        result.debug_prnd = tag.prnd;
        result.debug_adkd = tag.adkd;
        result.debug_tag_cop = tag.cop;
        result.debug_has_nav = false;
        result.debug_has_key = false;
        result.debug_has_mac_input = false;

        const GnssTime tag_nav_time =
            NavDataLookupTime(mack.subframe_epoch,
                tag.adkd);

        const GalileoNavCandidate* candidate =
            nav_store.FindForAdkd(tag.prnd,
                tag.adkd,
                tag_nav_time,
                tag.cop);

        result.debug_has_nav = (candidate != nullptr);

        if (candidate == nullptr)
        {
#if OSNMA_VERBOSE_NAVDATA
            static int32_t tag_missing_nav_debug_count = 0;

            if (tag_missing_nav_debug_count < 80)
            {
                printf("NAVDATA lookup failed: stage=3 prna=%d prnd=%d adkd=%d ctr=%d tag_index=%d tag_cop=%d raw_prnd=%d raw_adkd=%d mack_wn=%d mack_tow=%.0f requested_wn=%d requested_tow=%.0f\n",
                    mack.prn,
                    tag.prnd,
                    static_cast<int32_t>(tag.adkd),
                    tag.index + 1,
                    tag.index,
                    tag.cop,
                    raw_tag.prnd,
                    static_cast<int32_t>(raw_tag.adkd),
                    mack.subframe_epoch.wn,
                    mack.subframe_epoch.tow,
                    tag_nav_time.wn,
                    tag_nav_time.tow);

                ++tag_missing_nav_debug_count;
            }
#endif

            continue;
        }

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
        result.debug_has_key = true;

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
        result.debug_has_mac_input = true;

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
            AddSuccess(result,
                mack.prn,
                tag.prnd,
                tag.adkd,
                tag.index,
                tag.tag_size_bits,
                tag_nav_time,
                NavFingerprintFromMacInput(mac_input, false),
                *candidate);
            continue;
        }

        static int32_t tag_mismatch_debug_count = 0;

        if (tag_mismatch_debug_count < 160)
        {
            const double nav_age_s =
                DiffSeconds(tag_nav_time,
                    candidate->creation_time);

            printf("TAG MAC mismatch: stage=3 prna=%d prnd=%d adkd=%d ctr=%d tag_index=%d cop=%d raw_prnd=%d raw_adkd=%d "
                "mack_wn=%d mack_tow=%.0f requested_tow=%.0f selected_tow=%.0f nav_age_s=%.0f "
                "nmas=%u key_first=%02X mac_input_size=%d ",
                mack.prn,
                tag.prnd,
                static_cast<int32_t>(tag.adkd),
                tag.index + 1,
                tag.index,
                tag.cop,
                raw_tag.prnd,
                static_cast<int32_t>(raw_tag.adkd),
                mack.subframe_epoch.wn,
                mack.subframe_epoch.tow,
                tag_nav_time.tow,
                candidate->creation_time.tow,
                nav_age_s,
                static_cast<unsigned int>(nmas & 0x03u),
                key_size_bytes > 0 ? key[0] : 0,
                static_cast<int32_t>(mac_input.size()));

            PrintHexPrefix("rx=",
                tag.tag.data(),
                tag.tag_size_bytes,
                tag.tag_size_bytes);

            printf(" ");

            PrintHexPrefix("calc=",
                computed.data(),
                tag.tag_size_bytes,
                tag.tag_size_bytes);

            printf(" ");

            PrintHexFull("key=",
                key,
                key_size_bytes);

            printf(" ");

            PrintHexFull("input=",
                mac_input.data(),
                static_cast<int32_t>(mac_input.size()));

            printf("\n");

            ++tag_mismatch_debug_count;
        }
    }

    if (result.success_count > 0)
    {
        result.state = AuthState::Yes;
        result.reason = AuthReason::None;
        return result;
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
    const int32_t computed_macseq =
        (static_cast<int32_t>(computed[0]) << 4) |
        ((static_cast<int32_t>(computed[1]) >> 4) & 0x0F);


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

    if (mack.tag_info_count < 0 ||
        mack.tag_info_count > OsnmaMackMessage::MAX_TAGS)
    {
        return false;
    }

    out.reserve(5 + 2 * mack.tag_info_count);

    out.push_back(static_cast<std::uint8_t>(mack.prn));

    AppendGstSf32(mack.subframe_epoch,
        out);

    /*
        MACSEQ input:

            PRNA || GST_SF || Tag-Info of FLX slots

        This matches MACLT handling used by public OSNMA implementations:
        do not include all Tag-Info fields, only the fields whose MACLT slot
        is FLX for the current MACK subframe.

        The Tag-Info bytes are copied from the raw received MACK bits instead
        of reconstructed from decoded enum values, so reserved/dummy values are
        preserved exactly.
    */
    const int32_t mack_header_bits =
        mack.tag_size_bits + 12 + 4;

    const int32_t tag_and_info_bits =
        mack.tag_size_bits + 16;

    if (mack_header_bits <= 0 || tag_and_info_bits <= 0)
        return false;

    for (int32_t i = 0; i < mack.tag_info_count; ++i)
    {
        OsnmaMacLookupSlot slot{};

        if (!OsnmaMacLookupTable::GetExpectedSlot(maclt,
            mack.subframe_epoch,
            i + 1,
            slot))
        {
            return false;
        }

        if (slot.target != OsnmaMacTagAuthTarget::Flexible)
            continue;

        const int32_t tag_info_start =
            mack_header_bits +
            i * tag_and_info_bits +
            mack.tag_size_bits;

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
