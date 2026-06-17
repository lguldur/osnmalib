#include "osnma_engine.h"

#include <cstdio>
#include <cmath>

void OsnmaEngine::Reset()
{
    dsm_assembler_.Reset();
    trust_store_.Reset();
    nav_candidate_store_.Reset();
    tesla_chain_.Reset();

    for (auto& p : pending_macks_)
        p = PendingMack{};

    authenticated_objects_.clear();

    statistics_ = Statistics{};
}

const OsnmaEngine::Statistics& OsnmaEngine::GetStatistics() const
{
    return statistics_;
}

void OsnmaEngine::SetNavTimingMode(NavTimingMode mode)
{
    nav_candidate_store_.SetNavTimingMode(mode);
}

NavTimingMode OsnmaEngine::GetNavTimingMode() const
{
    return nav_candidate_store_.GetNavTimingMode();
}

bool OsnmaEngine::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return trust_store_.SetMerkleRoot(root_32_bytes);
}

bool OsnmaEngine::AddTrustedPublicKey(const OsnmaDsmPkr& public_key)
{
    GnssTime time{};
    time.wn = 0;
    time.tow = 0.0;

    return trust_store_.AddTrustedPublicKey(public_key, time);
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

            if (!tesla_chain_.IsInitialized())
            {
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

    const OsnmaTeslaChain::DisclosedKeyResult key_result =
        tesla_chain_.VerifyAndStoreDisclosedKeyDetailed(mack);

    if (key_result.status == OsnmaTeslaChain::DisclosedKeyStatus::VerifiedNew)
    {
        ++statistics_.disclosed_keys_verified;
        ++statistics_.disclosed_keys_new;

        Result mack_result =
            ProcessMacksForDisclosedKey(*trusted_kroot,
                key_result.key_time);

        if (mack_result.state == AuthState::Yes)
            return mack_result;

        return MakePendingResult(subframe,
            source,
            raw_source,
            mack_result.reason);
    }

    if (key_result.status ==
        OsnmaTeslaChain::DisclosedKeyStatus::IgnoredSameOrOlder)
    {
        ++statistics_.disclosed_keys_ignored_same_or_older;

        return MakePendingResult(subframe,
            source,
            raw_source,
            AuthReason::WaitingForKey);
    }

    if (key_result.status == OsnmaTeslaChain::DisclosedKeyStatus::WaitingForKey)
    {
        return MakePendingResult(subframe,
            source,
            raw_source,
            key_result.reason);
    }

    ++statistics_.disclosed_keys_failed;

    return MakePendingResult(subframe,
        source,
        raw_source,
        key_result.reason);
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

void OsnmaEngine::RegisterMacSuccesses(const OsnmaMacVerifier::Result& mac_result)
{
    for (int32_t i = 0;
        i < mac_result.success_count &&
        i < OsnmaMacVerifier::Result::MAX_SUCCESS_RECORDS;
        ++i)
    {
        const OsnmaMacVerifier::Result::SuccessRecord& success =
            mac_result.success_records[i];

        if (success.prnd <= 0 || !IsTimeValid(success.nav_time))
            continue;

        const AuthenticatedObjectKey key =
            std::make_tuple(success.prnd,
                static_cast<int32_t>(success.adkd),
                success.nav_fingerprint);

        AuthenticatedObjectState& state = authenticated_objects_[key];

        const bool first_authentication = (state.auth_bits == 0);

        state.auth_bits += success.tag_bits;

        ++statistics_.authenticated_tag_success;
        statistics_.authenticated_auth_bits_total += success.tag_bits;

        if (!first_authentication)
            continue;

        ++statistics_.authenticated_object_updates;

        if (success.adkd == OsnmaAdkd::InavCed)
        {
            ++statistics_.authenticated_ced_status_objects;
            printf("OSNMA auth: new CED and status for E%02d authenticated "
                "(authbits=%lld, GST={wn=%d,tow=%.0f})\n",
                success.prnd,
                static_cast<long long>(state.auth_bits),
                success.nav_time.wn,
                success.nav_time.tow);
        }
        else if (success.adkd == OsnmaAdkd::InavTiming)
        {
            ++statistics_.authenticated_timing_objects;
            printf("OSNMA auth: new timing parameters for E%02d authenticated "
                "(authbits=%lld, GST={wn=%d,tow=%.0f})\n",
                success.prnd,
                static_cast<long long>(state.auth_bits),
                success.nav_time.wn,
                success.nav_time.tow);
        }
        else if (success.adkd == OsnmaAdkd::SlowMac)
        {
            ++statistics_.authenticated_slow_mac_objects;
            printf("OSNMA auth: new slow MAC object for E%02d authenticated "
                "(authbits=%lld, GST={wn=%d,tow=%.0f})\n",
                success.prnd,
                static_cast<long long>(state.auth_bits),
                success.nav_time.wn,
                success.nav_time.tow);
        }
        else
        {
            printf("OSNMA auth: new ADKD %d object for E%02d authenticated "
                "(authbits=%lld, GST={wn=%d,tow=%.0f})\n",
                static_cast<int32_t>(success.adkd),
                success.prnd,
                static_cast<long long>(state.auth_bits),
                success.nav_time.wn,
                success.nav_time.tow);
        }
    }
}

bool OsnmaEngine::IsSameSubframeTime(const GnssTime& a,
    const GnssTime& b)
{
    if (!IsTimeValid(a) || !IsTimeValid(b))
        return false;

    return std::fabs(DiffSeconds(a, b)) < 0.5;
}

GnssTime OsnmaEngine::AddSecondsNormalized(const GnssTime& time,
    double seconds)
{
    GnssTime result = time;
    result.tow += seconds;

    while (result.tow < 0.0)
    {
        --result.wn;
        result.tow += 604800.0;
    }

    while (result.tow >= 604800.0)
    {
        ++result.wn;
        result.tow -= 604800.0;
    }

    return result;
}

OsnmaEngine::Result
OsnmaEngine::ProcessMacksForDisclosedKey(const OsnmaDsmKroot& trusted_kroot,
    const GnssTime& disclosed_key_time)
{
    Result result{};
    result.state = AuthState::Unknown;
    result.reason = AuthReason::WaitingForKey;
    result.auth_record_count = 0;

    if (!IsTimeValid(disclosed_key_time))
    {
        result.reason = AuthReason::InvalidTime;
        return result;
    }

    const GnssTime target_mack_time =
        AddSecondsNormalized(disclosed_key_time,
            -30.0);

    bool saw_target_mack = false;
    bool saw_missing_nav = false;
    bool saw_waiting_key = false;

    ++statistics_.pending_verification_runs;

    for (int32_t i = 0; i < MAX_PENDING_MACKS; ++i)
    {
        PendingMack& pending = pending_macks_[i];

        if (!pending.valid)
            continue;

        if (!IsSameSubframeTime(pending.mack.subframe_epoch,
            target_mack_time))
        {
            continue;
        }

        saw_target_mack = true;
        ++statistics_.pending_macks_checked;

        const OsnmaMacVerifier::Result mac_result =
            mac_verifier_.Verify(pending.mack,
                nav_candidate_store_,
                tesla_chain_,
                trusted_kroot.mac_function,
                pending.nmas,
                disclosed_key_time);

        if (mac_result.state == AuthState::Yes)
        {
            ++statistics_.pending_macks_verified_ok;
            ++statistics_.auth_success;
            RegisterMacSuccesses(mac_result);
            RemovePendingMack(i);

            result.state = AuthState::Yes;
            result.reason = AuthReason::None;
            continue;
        }

        if (mac_result.reason == AuthReason::MissingNavData)
        {
            ++statistics_.pending_missing_navdata;
            saw_missing_nav = true;

            /*
                Daniel processes a MACK once, when its disclosed key becomes
                newly trusted. If the corresponding navigation data is not
                available at that point, this MACK is not retried in a broad
                pending queue.
            */
            RemovePendingMack(i);
            continue;
        }

        if (mac_result.reason == AuthReason::WaitingForKey)
        {
            ++statistics_.pending_waiting_for_key;
            saw_waiting_key = true;

            /*
                This can happen for delayed slow-MAC material. Keep the MACK so
                future slow-MAC handling can consume it; do not classify it as a
                current MACK failure.
            */
            continue;
        }

        if (mac_result.reason == AuthReason::MackVerificationFailed &&
            mac_result.debug_stage == 1)
        {
            /*
                Daniel only processes tags for MACKs that pass MACSEQ/MACLT
                consistency. MACK-like blocks that fail at this stage are not
                navigation-data authentication failures; keep them separate
                from terminal tag failures and do not spam the normal log.
            */
            ++statistics_.pending_macks_skipped_macseq;
            RemovePendingMack(i);
            continue;
        }

        if (mac_result.reason == AuthReason::MackVerificationFailed ||
            mac_result.reason == AuthReason::UnsupportedMessage ||
            mac_result.reason == AuthReason::InvalidFrameFormat)
        {
            ++statistics_.pending_macks_terminal_failed;

            if (mac_result.reason == AuthReason::MackVerificationFailed &&
                (mac_result.debug_stage == 2 || mac_result.debug_stage == 3))
            {
                ++statistics_.pending_macks_failed_tag;
            }
            else
            {
                ++statistics_.pending_macks_failed_other;
            }

            printf("MACK validation failed at disclosed-key schedule: "
                "reason=%d stage=%d mack_prn=%d tag_index=%d ctr=%d "
                "prnd=%d adkd=%d tag_cop=%d mack_wn=%d mack_tow=%.0f "
                "key_wn=%d key_tow=%.0f macseq=%d mack_cop=%d "
                "has_nav=%d has_key=%d has_mac_input=%d\n",
                static_cast<int32_t>(mac_result.reason),
                mac_result.debug_stage,
                mac_result.debug_mack_prn,
                mac_result.debug_tag_index,
                mac_result.debug_ctr,
                mac_result.debug_prnd,
                static_cast<int32_t>(mac_result.debug_adkd),
                mac_result.debug_tag_cop,
                mac_result.debug_mack_wn,
                mac_result.debug_mack_tow,
                disclosed_key_time.wn,
                disclosed_key_time.tow,
                mac_result.debug_macseq,
                mac_result.debug_mack_cop,
                mac_result.debug_has_nav ? 1 : 0,
                mac_result.debug_has_key ? 1 : 0,
                mac_result.debug_has_mac_input ? 1 : 0);

            RemovePendingMack(i);

            if (result.state != AuthState::Yes)
                result.reason = mac_result.reason;

            continue;
        }
    }

    if (result.state == AuthState::Yes)
        return result;

    if (!saw_target_mack)
        result.reason = AuthReason::WaitingForMoreFrames;
    else if (saw_waiting_key)
        result.reason = AuthReason::WaitingForKey;
    else if (saw_missing_nav)
        result.reason = AuthReason::MissingNavData;

    return result;
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
            RegisterMacSuccesses(mac_result);
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
            static int32_t missing_nav_debug_count = 0;

            if (mac_result.reason == AuthReason::MissingNavData &&
                missing_nav_debug_count < 50)
            {
                printf("TAG missing navdata: "
                    "stage=%d mack_prn=%d tag_index=%d ctr=%d "
                    "prnd=%d adkd=%d tag_cop=%d mack_wn=%d mack_tow=%.0f "
                    "macseq=%d mack_cop=%d has_nav=%d has_key=%d has_mac_input=%d\n",
                    mac_result.debug_stage,
                    mac_result.debug_mack_prn,
                    mac_result.debug_tag_index,
                    mac_result.debug_ctr,
                    mac_result.debug_prnd,
                    static_cast<int32_t>(mac_result.debug_adkd),
                    mac_result.debug_tag_cop,
                    mac_result.debug_mack_wn,
                    mac_result.debug_mack_tow,
                    mac_result.debug_macseq,
                    mac_result.debug_mack_cop,
                    mac_result.debug_has_nav ? 1 : 0,
                    mac_result.debug_has_key ? 1 : 0,
                    mac_result.debug_has_mac_input ? 1 : 0);

                ++missing_nav_debug_count;
            }

            ++statistics_.pending_missing_navdata;
            saw_missing_nav = true;
            continue;
        }

        /*
            MACSEQ mismatches are kept separate from tag authentication
            failures. Daniel's test-vector runner does not expose these as
            visible authentication failures for configuration_1, so they are
            counted as skipped MACKs here instead of polluting the terminal
            tag-failure counter.
        */
        if (mac_result.reason == AuthReason::MackVerificationFailed &&
            mac_result.debug_stage == 1)
        {
            ++statistics_.pending_macks_skipped_macseq;
            RemovePendingMack(i);
            continue;
        }

        /*
            At this point the relevant key was available and the MAC path
            reached a real terminal failure for this pending MACK.
        */
        if (mac_result.reason == AuthReason::MackVerificationFailed ||
            mac_result.reason == AuthReason::UnsupportedMessage ||
            mac_result.reason == AuthReason::InvalidFrameFormat)
        {
            ++statistics_.pending_macks_terminal_failed;

            if (mac_result.reason == AuthReason::MackVerificationFailed &&
                (mac_result.debug_stage == 2 || mac_result.debug_stage == 3))
            {
                ++statistics_.pending_macks_failed_tag;
            }
            else
            {
                ++statistics_.pending_macks_failed_other;
            }

            printf("TAG terminal failed: "
                "reason=%d stage=%d mack_prn=%d tag_index=%d ctr=%d "
                "prnd=%d adkd=%d tag_cop=%d mack_wn=%d mack_tow=%.0f "
                "macseq=%d mack_cop=%d has_nav=%d has_key=%d has_mac_input=%d\n",
                static_cast<int32_t>(mac_result.reason),
                mac_result.debug_stage,
                mac_result.debug_mack_prn,
                mac_result.debug_tag_index,
                mac_result.debug_ctr,
                mac_result.debug_prnd,
                static_cast<int32_t>(mac_result.debug_adkd),
                mac_result.debug_tag_cop,
                mac_result.debug_mack_wn,
                mac_result.debug_mack_tow,
                mac_result.debug_macseq,
                mac_result.debug_mack_cop,
                mac_result.debug_has_nav ? 1 : 0,
                mac_result.debug_has_key ? 1 : 0,
                mac_result.debug_has_mac_input ? 1 : 0);

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
