#include "osnma_engine.h"

void OsnmaEngine::Reset()
{
    dsm_assembler_.Reset();
    trust_store_.Reset();
    nav_candidate_store_.Reset();
    tesla_chain_.Reset();

    for (auto& p : pending_macks_)
        p = PendingMack{};

    statistics_ = Statistics{};
}

const OsnmaEngine::Statistics& OsnmaEngine::GetStatistics() const
{
    return statistics_;
}


bool OsnmaEngine::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return trust_store_.SetMerkleRoot(root_32_bytes);
}

bool OsnmaEngine::FeedNavigationPage(const GalileoInavPageParts& page,
    AuthReason& reason_out)
{
    ++statistics_.navigation_pages_received;

    return nav_candidate_store_.FeedPage(page, reason_out);
}

OsnmaEngine::Result
OsnmaEngine::ProcessSubframe(const OsnmaSubframe& subframe,
    NavSignalSource source,
    int32_t raw_source)
{
    ++statistics_.subframes_processed;

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

    if (block.dsm_header.dsm_id >= 0 &&
        block.dsm_header.dsm_id < static_cast<int32_t>(statistics_.dsm_bid_count.size()) &&
        block.dsm_header.block_id >= 0 &&
        block.dsm_header.block_id < static_cast<int32_t>(statistics_.dsm_bid_count[0].size()))
    {
        ++statistics_.dsm_bid_count[block.dsm_header.dsm_id][block.dsm_header.block_id];
    }

    ++statistics_.dsm_blocks_received;

    if (block.dsm_header.dsm_id >= 0 &&
        block.dsm_header.dsm_id < static_cast<int32_t>(statistics_.dsm_id_count.size()))
    {
        ++statistics_.dsm_id_count[block.dsm_header.dsm_id];
    }

    for (int32_t i = 0; i < OsnmaDsmBlock::SIZE_BYTES; ++i)
        block.data[i] = subframe.hkroot[i + 2];

    OsnmaDsmMessage message{};

    const bool complete =
        dsm_assembler_.FeedBlock(block, message);

    if (complete)
    {
        ++statistics_.dsm_messages_completed;

        if (message.dsm_id >= 0 &&
            message.dsm_id < static_cast<int32_t>(statistics_.dsm_completed_id_count.size()))
        {
            ++statistics_.dsm_completed_id_count[message.dsm_id];
        }

        OsnmaDecodedDsm decoded{};
        AuthReason decode_reason = AuthReason::None;

        /*printf("Completed DSM: PRN=%d DSM_ID=%d type=%d blocks=%d bytes=%d first=%02X %02X %02X %02X %02X %02X %02X %02X\n",
            message.prn,
            message.dsm_id,
            static_cast<int32_t>(message.type),
            message.block_count,
            message.byte_count,
            message.data[0],
            message.data[1],
            message.data[2],
            message.data[3],
            message.data[4],
            message.data[5],
            message.data[6],
            message.data[7]);
        */

        const bool decoded_ok =
            dsm_content_decoder_.Decode(message,
                decoded,
                decode_reason);

        if (!decoded_ok)
        {
            ++statistics_.dsm_decode_failed;

            const int32_t reason_index =
                static_cast<int32_t>(decode_reason);

            if (reason_index >= 0 &&
                reason_index < static_cast<int32_t>(statistics_.dsm_decode_failed_reason_count.size()))
            {
                ++statistics_.dsm_decode_failed_reason_count[reason_index];
            }

            return MakePendingResult(subframe,
                source,
                raw_source,
                decode_reason);
        }

        ++statistics_.dsm_decode_ok;

        if (decoded.type == OsnmaDsmType::Pkr &&
            decoded.pkr.valid_layout)
        {
            ++statistics_.pkr_received;

            const bool verified =
                trust_store_.AddPkr(decoded.pkr,
                    subframe.subframe_epoch);

            if (!verified)
            {
                ++statistics_.pkr_failed;

                const AuthReason pkr_reason =
                    AuthReason::MerkleVerificationFailed;

                const int32_t reason_index =
                    static_cast<int32_t>(pkr_reason);

                if (reason_index >= 0 &&
                    reason_index < static_cast<int32_t>(statistics_.pkr_failed_reason_count.size()))
                {
                    ++statistics_.pkr_failed_reason_count[reason_index];
                }

                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    pkr_reason);
            }

            ++statistics_.pkr_verified;
        }

        if (decoded.type == OsnmaDsmType::Kroot &&
            decoded.kroot.valid_layout)
        {
            ++statistics_.kroot_received;

            printf("KROOT decoded: DSM_ID=%d PKID=%d CID=%d HF=%d MF=%d KS=%d TS=%d MACLT=%d WN=%d TOWH=%d\n",
                message.dsm_id,
                decoded.kroot.public_key_id,
                decoded.kroot.kroot_chain_id,
                static_cast<int32_t>(decoded.kroot.hash_function),
                static_cast<int32_t>(decoded.kroot.mac_function),
                decoded.kroot.key_size_bits,
                decoded.kroot.tag_size_bits,
                decoded.kroot.mac_lookup_table,
                decoded.kroot.kroot_wn,
                decoded.kroot.kroot_towh);

            const bool verified =
                trust_store_.AddKroot(decoded.kroot,
                    subframe.subframe_epoch);

            if (!verified)
            {
                ++statistics_.kroot_failed;

                const AuthReason kroot_reason =
                    AuthReason::SignatureVerificationFailed;

                const int32_t reason_index =
                    static_cast<int32_t>(kroot_reason);

                if (reason_index >= 0 &&
                    reason_index < static_cast<int32_t>(statistics_.kroot_failed_reason_count.size()))
                {
                    ++statistics_.kroot_failed_reason_count[reason_index];
                }

                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    kroot_reason);
            }

            ++statistics_.kroot_verified;

            AuthReason tesla_reason = AuthReason::None;

            if (!tesla_chain_.InitializeFromKroot(decoded.kroot,
                tesla_reason))
            {
                ++statistics_.tesla_init_failed;

                return MakePendingResult(subframe,
                    source,
                    raw_source,
                    tesla_reason);
            }

            ++statistics_.tesla_initialized;
        }
    }

    const OsnmaDsmKroot* trusted_kroot =
        trust_store_.GetTrustedKroot();

    if (trusted_kroot == nullptr)
    {
        ++statistics_.subframes_waiting_for_kroot;

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
        ++statistics_.mack_parse_failed;

        return MakePendingResult(subframe,
            source,
            raw_source,
            mack_reason);
    }

    ++statistics_.mack_parse_ok;

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
        ++statistics_.disclosed_keys_failed;

        return MakePendingResult(subframe,
            source,
            raw_source,
            tesla_reason);
    }

    ++statistics_.disclosed_keys_verified;

    Result pending_result =
        VerifyPendingMacks(*trusted_kroot,
            subframe.subframe_epoch);

    if (pending_result.state == AuthState::Yes)
    {
        ++statistics_.auth_success;
        return pending_result;
    }

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
        ++statistics_.pending_macks_overwritten;

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

    ++statistics_.macks_added_pending;
    UpdatePendingMackStatistics();
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
            ++statistics_.pending_macks_cleaned;
            continue;
        }

        const double age_s =
            DiffSeconds(now, p.mack.subframe_epoch);

        if (age_s < 0.0 || age_s > PENDING_MACK_LIFETIME_S)
        {
            p = PendingMack{};
            ++statistics_.pending_macks_cleaned;
        }
    }

    UpdatePendingMackStatistics();
}

void OsnmaEngine::RemovePendingMack(int32_t index)
{
    if (index < 0 || index >= MAX_PENDING_MACKS)
        return;

    pending_macks_[index] = PendingMack{};
    UpdatePendingMackStatistics();
}

void OsnmaEngine::UpdatePendingMackStatistics()
{
    int32_t count = 0;

    for (const auto& pending : pending_macks_)
    {
        if (pending.valid)
            ++count;
    }

    statistics_.pending_macks_current = count;

    if (count > statistics_.pending_macks_max_seen)
        statistics_.pending_macks_max_seen = count;
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

    ++statistics_.pending_verification_runs;

    for (int32_t i = 0; i < MAX_PENDING_MACKS; ++i)
    {
        PendingMack& pending = pending_macks_[i];

        if (!pending.valid)
            continue;

        saw_pending = true;
        ++statistics_.pending_macks_checked;

        const OsnmaMacVerifier::Result mac_result =
            mac_verifier_.Verify(pending.mack,
                nav_candidate_store_,
                tesla_chain_,
                trusted_kroot.mac_function,
                pending.nmas,
                pending.mack.subframe_epoch);

        if (mac_result.state == AuthState::Yes)
        {
            ++statistics_.pending_macks_verified_ok;
            RemovePendingMack(i);

            result.state = AuthState::Yes;
            result.reason = AuthReason::None;
            result.auth_record_count = 0;
            return result;
        }

        if (mac_result.reason == AuthReason::WaitingForKey)
        {
            ++statistics_.pending_waiting_for_key;
            saw_waiting_key = true;
            continue;
        }

        if (mac_result.reason == AuthReason::MissingNavData)
        {
            ++statistics_.pending_missing_navdata;
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
            ++statistics_.pending_macks_terminal_failed;

            /*printf("TAG terminal failed: "
                "mack_prn=%d tag_index=%d ctr=%d prnd=%d adkd=%d "
                "mack_tow=%d key_tow=%d has_nav=%d\n",
                pending.mack.prn,
                tag.index,
                tag.index + 1,
                tag.prnd,
                static_cast<int32_t>(tag.adkd),
                pending.mack.subframe_epoch.tow,
                disclosed_key_time.tow,
                has_nav_data ? 1 : 0);*/

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
