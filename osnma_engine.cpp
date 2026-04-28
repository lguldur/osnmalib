#include "osnma_engine.h"

void OsnmaEngine::Reset()
{
    dsm_assembler_.Reset();
    trust_store_.Reset();
    nav_candidate_store_.Reset();
    tesla_chain_.Reset();
}

bool OsnmaEngine::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return trust_store_.SetMerkleRoot(root_32_bytes);
}

bool OsnmaEngine::FeedNavigationPage(const GalileoInavPageParts& page,
    AuthReason& reason_out)
{
    return nav_candidate_store_.FeedPage(page, reason_out);
}

OsnmaEngine::Result
OsnmaEngine::ProcessSubframe(const OsnmaSubframe& subframe,
    NavSignalSource source,
    int32_t raw_source)
{
    nav_candidate_store_.Cleanup(subframe.subframe_epoch);

    OsnmaDsmBlock block{};

    block.prn = subframe.prn;
    block.subframe_epoch = subframe.subframe_epoch;

    block.nma_header.raw =
        static_cast<std::uint8_t>(subframe.hkroot[0]);

    const std::uint8_t nmas =
        static_cast<std::uint8_t>((block.nma_header.raw >> 6) & 0x03u);

    block.dsm_header =
        OsnmaDsmAssembler::ParseDsmHeader(
            static_cast<std::uint8_t>(subframe.hkroot[1]));

    for (int32_t i = 0; i < OsnmaDsmBlock::SIZE_BYTES; ++i)
        block.data[i] = subframe.hkroot[i + 2];

    OsnmaDsmMessage message{};

    const bool complete =
        dsm_assembler_.FeedBlock(block, message);

    if (complete)
    {
        OsnmaDecodedDsm decoded{};
        AuthReason decode_reason = AuthReason::None;

        const bool decoded_ok =
            dsm_content_decoder_.Decode(message,
                decoded,
                decode_reason);

        if (!decoded_ok)
        {
            return MakePendingResult(subframe,
                source,
                raw_source,
                decode_reason);
        }

        if (decoded.type == OsnmaDsmType::Pkr &&
            decoded.pkr.valid_layout)
        {
            const bool verified =
                trust_store_.AddPkr(decoded.pkr,
                    subframe.subframe_epoch);

            if (!verified)
            {
                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    AuthReason::MerkleVerificationFailed);
            }
        }

        if (decoded.type == OsnmaDsmType::Kroot &&
            decoded.kroot.valid_layout)
        {
            const bool verified =
                trust_store_.AddKroot(decoded.kroot,
                    subframe.subframe_epoch);

            if (!verified)
            {
                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    AuthReason::SignatureVerificationFailed);
            }

            AuthReason tesla_reason = AuthReason::None;

            if (!tesla_chain_.InitializeFromKroot(decoded.kroot,
                tesla_reason))
            {
                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    tesla_reason);
            }
        }
    }

    const OsnmaDsmKroot* trusted_kroot =
        trust_store_.GetTrustedKroot();

    if (trusted_kroot == nullptr)
    {
        return MakePendingResult(subframe,
            source,
            raw_source,
            AuthReason::WaitingForKey);
    }

    OsnmaMackMessage mack{};
    AuthReason mack_reason = AuthReason::None;

    const bool mack_ok =
        mack_processor_.ParseMack(subframe,
            trusted_kroot->key_size_bits,
            trusted_kroot->tag_size_bits,
            mack,
            mack_reason);

    if (!mack_ok)
    {
        return MakePendingResult(subframe,
            source,
            raw_source,
            mack_reason);
    }

    AuthReason tesla_reason = AuthReason::None;

    const bool tesla_ok =
        tesla_chain_.VerifyAndStoreDisclosedKey(mack,
            tesla_reason);

    if (!tesla_ok)
    {
        return MakePendingResult(subframe,
            source,
            raw_source,
            tesla_reason);
    }

    const OsnmaMacVerifier::Result mac_result =
        mac_verifier_.Verify(mack,
            nav_candidate_store_,
            tesla_chain_,
            trusted_kroot->mac_function,
            nmas,
            subframe.subframe_epoch);

    if (mac_result.state == AuthState::Yes)
    {
        Result result{};
        result.state = AuthState::Yes;
        result.reason = AuthReason::None;
        result.auth_record_count = 0;
        return result;
    }

    return MakePendingResult(subframe,
        source,
        raw_source,
        mac_result.reason);
}

OsnmaEngine::Result
OsnmaEngine::MakePendingResult(const OsnmaSubframe& subframe,
    NavSignalSource source,
    int32_t raw_source,
    AuthReason reason) const
{
    Result result{};
    result.state = AuthState::Unknown;
    result.reason = reason;
    result.auth_record_count = 0;

    (void)subframe;
    (void)source;
    (void)raw_source;

    return result;
}
