#include "osnma_engine.h"

void OsnmaEngine::Reset()
{
    dsm_assembler_.Reset();
    trust_store_.Reset();
    nav_candidate_store_.Reset();
    tesla_chain_.Reset();

    for (auto& p : pending_macks_)
        p = PendingMack{};
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
    CleanupPendingMacks(subframe.subframe_epoch);

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

    /*
        Store this MACK for future verification.

        The disclosed TESLA key in this MACK authenticates previous MACKs,
        not this same MACK. Current MACK verification will happen when a
        later disclosed key becomes available.
    */
    AddPendingMack(mack,
        nmas,
        source,
        raw_source);

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

    Result pending_result =
        VerifyPendingMacks(*trusted_kroot,
            subframe.subframe_epoch);

    if (pending_result.state == AuthState::Yes)
        return pending_result;

    return MakePendingResult(subframe,
        source,
        raw_source,
        pending_result.reason);
}

void OsnmaEngine::AddPendingMack(const OsnmaMackMessage& mack,
    std::uint8_t nmas,
    NavSignalSource source,
    int32_t raw_source)
{
    int32_t slot = -1;

    for (int32_t i = 0; i < MAX_PENDING_MACKS; ++i)
    {
        if (!pending_macks_[i].valid)
        {
            slot = i;
            break;
        }
    }

    if (slot < 0)
    {
        slot = 0;

        for (int32_t i = 1; i < MAX_PENDING_MACKS; ++i)
        {
            const double dt =
                DiffSeconds(pending_macks_[i].mack.subframe_epoch,
                    pending_macks_[slot].mack.subframe_epoch);

            if (dt < 0.0)
                slot = i;
        }
    }

    PendingMack& p = pending_macks_[slot];

    p = PendingMack{};
    p.valid = true;
    p.mack = mack;
    p.nmas = nmas;
    p.source = source;
    p.raw_source = raw_source;
}

void OsnmaEngine::CleanupPendingMacks(const GnssTime& now)
{
    if (!IsTimeValid(now))
        return;

    for (int32_t i = 0; i < MAX_PENDING_MACKS; ++i)
    {
        PendingMack& p = pending_macks_[i];

        if (!p.valid)
            continue;

        if (!IsTimeValid(p.mack.subframe_epoch))
        {
            p = PendingMack{};
            continue;
        }

        const double age_s =
            DiffSeconds(now, p.mack.subframe_epoch);

        if (age_s < 0.0 || age_s > PENDING_MACK_LIFETIME_S)
            p = PendingMack{};
    }
}

void OsnmaEngine::RemovePendingMack(int32_t index)
{
    if (index < 0 || index >= MAX_PENDING_MACKS)
        return;

    pending_macks_[index] = PendingMack{};
}

OsnmaEngine::Result
OsnmaEngine::VerifyPendingMacks(const OsnmaDsmKroot& trusted_kroot,
    const GnssTime& now)
{
    Result result{};
    result.state = AuthState::Unknown;
    result.reason = AuthReason::WaitingForKey;
    result.auth_record_count = 0;

    bool saw_pending = false;
    bool saw_waiting_key = false;
    bool saw_missing_nav = false;

    for (int32_t i = 0; i < MAX_PENDING_MACKS; ++i)
    {
        PendingMack& pending = pending_macks_[i];

        if (!pending.valid)
            continue;

        saw_pending = true;

        const OsnmaMacVerifier::Result mac_result =
            mac_verifier_.Verify(pending.mack,
                nav_candidate_store_,
                tesla_chain_,
                trusted_kroot.mac_function,
                pending.nmas,
                pending.mack.subframe_epoch);

        if (mac_result.state == AuthState::Yes)
        {
            RemovePendingMack(i);

            result.state = AuthState::Yes;
            result.reason = AuthReason::None;
            result.auth_record_count = 0;
            return result;
        }

        if (mac_result.reason == AuthReason::WaitingForKey)
        {
            saw_waiting_key = true;
            continue;
        }

        if (mac_result.reason == AuthReason::MissingNavData)
        {
            saw_missing_nav = true;
            continue;
        }

        /*
            At this point the relevant key was available and the MAC path
            reached a terminal failure for this pending MACK.
        */
        if (mac_result.reason == AuthReason::MackVerificationFailed ||
            mac_result.reason == AuthReason::UnsupportedMessage ||
            mac_result.reason == AuthReason::InvalidFrameFormat)
        {
            RemovePendingMack(i);
            result.reason = mac_result.reason;
        }
    }

    if (!saw_pending)
    {
        result.reason = AuthReason::WaitingForKey;
    }
    else if (saw_waiting_key)
    {
        result.reason = AuthReason::WaitingForKey;
    }
    else if (saw_missing_nav)
    {
        result.reason = AuthReason::MissingNavData;
    }

    return result;
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
