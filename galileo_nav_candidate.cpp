#include "galileo_nav_candidate.h"

#include <cstdio>
#include <cstring>

#include "osnma_bit_utils.h"

bool GalileoNavCandidate::HasWord(int32_t wt) const
{
    if (wt < 0 || wt > GAL_MAX_WT)
        return false;

    return words[wt].valid;
}

bool GalileoNavCandidate::HasCedData() const
{
    return HasWord(GAL_WT1) &&
        HasWord(GAL_WT2) &&
        HasWord(GAL_WT3) &&
        HasWord(GAL_WT4) &&
        HasWord(GAL_WT5);
}

bool GalileoNavCandidate::HasTimingData() const
{
    if (!HasWord(GAL_WT6) || !HasWord(GAL_WT10))
        return false;

    const GalileoNavWord& wt6 = words[GAL_WT6];
    const GalileoNavWord& wt10 = words[GAL_WT10];

    if (!wt6.has_epoch || !wt10.has_epoch)
        return false;

    if (!IsTimeValid(wt6.page_epoch) ||
        !IsTimeValid(wt10.page_epoch))
    {
        return false;
    }

    const double dt_s =
        DiffSeconds(wt10.page_epoch, wt6.page_epoch);

    if (dt_s < 0.0)
        return false;

    return dt_s <= 240.0;
}

bool GalileoNavCandidate::IsComplete() const
{
    return HasCedData();
}

void GalileoNavCandidateStore::Reset()
{
    candidates_.clear();
}

bool GalileoNavCandidateStore::FeedPage(const GalileoInavPageParts& page,
    AuthReason& reason_out)
{
    reason_out = AuthReason::None;

    if (page.prn <= 0)
    {
        reason_out = AuthReason::InvalidPrn;
        return false;
    }

    if (!page.crc_ok)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (!IsTimeValid(page.page_epoch))
    {
        reason_out = AuthReason::InvalidTime;
        return false;
    }

    if (page.even == nullptr || page.odd == nullptr)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    Cleanup(page.page_epoch);

    const PageHeader header = ExtractPageHeader(page);

    if (!header.valid)
    {
        reason_out = AuthReason::UnsupportedMessage;
        return false;
    }

    if (header.wt >= GAL_WT1 && header.wt <= GAL_WT5)
        return FeedCedPage(page, header, reason_out);

    if (header.wt == GAL_WT6 || header.wt == GAL_WT10)
        return FeedTimingPage(page, header, reason_out);

    reason_out = AuthReason::UnsupportedMessage;
    return false;
}

bool GalileoNavCandidateStore::FeedCedPage(const GalileoInavPageParts& page,
    const PageHeader& header,
    AuthReason& reason_out)
{
    const Key key(page.prn, header.iod);

    auto it = candidates_.find(key);

    if (it == candidates_.end())
    {
        if (header.wt != GAL_WT1)
        {
            static int32_t ced_reject_debug_count = 0;

            if (ced_reject_debug_count < 120)
            {
                printf("NAVDATA rejected: prn=%d wt=%d iod=%d toe=%d wn=%d tow=%.0f reason=no WT1 candidate with same iod\n",
                    page.prn,
                    header.wt,
                    header.iod,
                    header.toe,
                    page.page_epoch.wn,
                    page.page_epoch.tow);

                ++ced_reject_debug_count;
            }

            reason_out = AuthReason::WaitingForMoreFrames;
            return false;
        }

        GalileoNavCandidate candidate{};
        candidate.prn = page.prn;
        candidate.iod = header.iod;
        candidate.toe = header.toe;
        candidate.creation_time = page.page_epoch;
        candidate.last_update_time = page.page_epoch;

        StoreWord(candidate, page, header.wt);

        candidate.complete = candidate.IsComplete();

        candidates_[key] = candidate;

        reason_out = AuthReason::None;
        return true;
    }

    GalileoNavCandidate& candidate = it->second;

    if (!CanAcceptCedWord(candidate, header.wt))
    {
        static int32_t ced_order_debug_count = 0;

        if (ced_order_debug_count < 120)
        {
            printf("NAVDATA rejected: prn=%d wt=%d iod=%d toe=%d wn=%d tow=%.0f reason=bad sequence have1=%d have2=%d have3=%d have4=%d have5=%d\n",
                page.prn,
                header.wt,
                header.iod,
                header.toe,
                page.page_epoch.wn,
                page.page_epoch.tow,
                candidate.HasWord(GAL_WT1) ? 1 : 0,
                candidate.HasWord(GAL_WT2) ? 1 : 0,
                candidate.HasWord(GAL_WT3) ? 1 : 0,
                candidate.HasWord(GAL_WT4) ? 1 : 0,
                candidate.HasWord(GAL_WT5) ? 1 : 0);

            ++ced_order_debug_count;
        }

        reason_out = AuthReason::WaitingForMoreFrames;
        return false;
    }

    if (candidate.HasWord(header.wt))
    {
        reason_out = AuthReason::WaitingForMoreFrames;
        return false;
    }

    if (candidate.toe >= 0 && header.toe >= 0 && candidate.toe != header.toe)
    {
        reason_out = AuthReason::TimeInconsistency;
        return false;
    }

    StoreWord(candidate, page, header.wt);

    candidate.last_update_time = page.page_epoch;
    candidate.complete = candidate.IsComplete();

    reason_out = AuthReason::None;
    return true;
}

bool GalileoNavCandidateStore::FeedTimingPage(const GalileoInavPageParts& page,
    const PageHeader& header,
    AuthReason& reason_out)
{
    const Key key(page.prn, -1);

    auto it = candidates_.find(key);

    if (it == candidates_.end())
    {
        GalileoNavCandidate candidate{};
        candidate.prn = page.prn;
        candidate.iod = -1;
        candidate.toe = -1;
        candidate.creation_time = page.page_epoch;
        candidate.last_update_time = page.page_epoch;

        if (header.wt == GAL_WT6)
        {
            StoreWord(candidate, page, header.wt);
            candidates_[key] = candidate;

            reason_out = AuthReason::None;
            return true;
        }

        // WT10 is accepted only after WT6.
        reason_out = AuthReason::WaitingForMoreFrames;
        return false;
    }

    GalileoNavCandidate& candidate = it->second;

    if (header.wt == GAL_WT6)
    {
        /*
            WT6 anchors an ADKD=4 timing pair.
            A new WT6 invalidates any old WT10 to avoid mixing generations.
        */
        StoreWord(candidate, page, GAL_WT6);
        ClearWord(candidate, GAL_WT10);

        candidate.last_update_time = page.page_epoch;

        reason_out = AuthReason::None;
        return true;
    }

    if (header.wt == GAL_WT10)
    {
        /*
            WT10 must belong to the current WT6-anchored timing pair.
        */
        if (!candidate.HasWord(GAL_WT6))
        {
            reason_out = AuthReason::WaitingForMoreFrames;
            return false;
        }

        const GalileoNavWord& wt6 = candidate.words[GAL_WT6];

        if (!wt6.has_epoch || !IsTimeValid(wt6.page_epoch))
        {
            reason_out = AuthReason::InvalidTime;
            return false;
        }

        const double dt_s =
            DiffSeconds(page.page_epoch, wt6.page_epoch);

        if (dt_s < 0.0 || dt_s > TIMING_PAIR_MAX_SPAN_S)
        {
            reason_out = AuthReason::TimeInconsistency;
            return false;
        }

        StoreWord(candidate, page, GAL_WT10);

        candidate.last_update_time = page.page_epoch;

        reason_out = AuthReason::None;
        return true;
    }

    reason_out = AuthReason::UnsupportedMessage;
    return false;
}

void GalileoNavCandidateStore::Cleanup(const GnssTime& now)
{
    if (!IsTimeValid(now))
        return;

    for (auto it = candidates_.begin(); it != candidates_.end(); )
    {
        if (IsExpired(it->second, now))
            it = candidates_.erase(it);
        else
            ++it;
    }
}

const GalileoNavCandidate*
GalileoNavCandidateStore::FindComplete(int32_t prn,
    int32_t iod,
    const GnssTime& now) const
{
    if (prn <= 0)
        return nullptr;

    if (!IsTimeValid(now))
        return nullptr;

    if (iod >= 0)
    {
        const Key key(prn, iod);

        auto it = candidates_.find(key);

        if (it == candidates_.end())
            return nullptr;

        const GalileoNavCandidate& candidate = it->second;

        if (!candidate.HasCedData())
            return nullptr;

        if (IsExpired(candidate, now))
            return nullptr;

        return &candidate;
    }

    const GalileoNavCandidate* best = nullptr;

    for (const auto& kv : candidates_)
    {
        const GalileoNavCandidate& candidate = kv.second;

        if (candidate.prn != prn)
            continue;

        if (!candidate.HasCedData())
            continue;

        if (IsExpired(candidate, now))
            continue;

        if (best == nullptr)
        {
            best = &candidate;
            continue;
        }

        const double candidate_age =
            DiffSeconds(now, candidate.last_update_time);

        const double best_age =
            DiffSeconds(now, best->last_update_time);

        if (candidate_age >= 0.0 &&
            best_age >= 0.0 &&
            candidate_age < best_age)
        {
            best = &candidate;
        }
    }

    return best;
}

const GalileoNavCandidate*
GalileoNavCandidateStore::FindForAdkd(int32_t prn,
    OsnmaAdkd adkd,
    const GnssTime& now) const
{
    if (adkd == OsnmaAdkd::InavCed ||
        adkd == OsnmaAdkd::SlowMac)
    {
        return FindComplete(prn, -1, now);
    }

    if (adkd == OsnmaAdkd::InavTiming)
    {
        const Key key(prn, -1);

        auto it = candidates_.find(key);

        if (it == candidates_.end())
            return nullptr;

        const GalileoNavCandidate& candidate = it->second;

        if (!candidate.HasTimingData())
            return nullptr;

        if (!IsValidTimingPair(candidate))
            return nullptr;

        if (IsExpired(candidate, now))
            return nullptr;

        return &candidate;
    }

    return nullptr;
}

GalileoNavCandidateStore::PageHeader
GalileoNavCandidateStore::ExtractPageHeader(const GalileoInavPageParts& page)
{
    PageHeader header{};

    if (page.even == nullptr)
        return header;

    /*
        Centralized Galileo I/NAV header extraction.

        IMPORTANT:
        These offsets assume the receiver provides the same 128-bit MSB-first
        INAV word image used by the OSNMA ADKD masks.
    */

    static constexpr int32_t WT_FIRST_BIT = 0;
    static constexpr int32_t WT_BIT_COUNT = 6;

    static constexpr int32_t IODNAV_FIRST_BIT = 6;
    static constexpr int32_t IODNAV_BIT_COUNT = 10;

    static constexpr int32_t TOE_FIRST_BIT = 16;
    static constexpr int32_t TOE_BIT_COUNT = 14;

    header.wt =
        GetUnsignedBitsMsb0(page.even,
            WT_FIRST_BIT,
            WT_BIT_COUNT);

    if (!IsSupportedWordType(header.wt))
        return header;

    if (header.wt >= GAL_WT1 && header.wt <= GAL_WT5)
    {
        header.iod =
            GetUnsignedBitsMsb0(page.even,
                IODNAV_FIRST_BIT,
                IODNAV_BIT_COUNT);

        header.toe =
            GetUnsignedBitsMsb0(page.even,
                TOE_FIRST_BIT,
                TOE_BIT_COUNT);

        if (header.iod < 0)
            return header;
    }
    else
    {
        header.iod = -1;
        header.toe = -1;
    }

    header.valid = true;
    return header;
}

bool GalileoNavCandidateStore::IsSupportedWordType(int32_t wt)
{
    return (wt >= GAL_WT1 && wt <= GAL_WT6) ||
        (wt == GAL_WT10);
}

bool GalileoNavCandidateStore::CanAcceptCedWord(const GalileoNavCandidate& candidate,
    int32_t wt)
{
    switch (wt)
    {
    case GAL_WT1:
        return false;

    case GAL_WT2:
        return candidate.HasWord(GAL_WT1);

    case GAL_WT3:
        return candidate.HasWord(GAL_WT2);

    case GAL_WT4:
        return candidate.HasWord(GAL_WT3);

    case GAL_WT5:
        return candidate.HasWord(GAL_WT4);

    default:
        return false;
    }
}

bool GalileoNavCandidateStore::IsExpired(const GalileoNavCandidate& candidate,
    const GnssTime& now)
{
    if (!IsTimeValid(candidate.creation_time) ||
        !IsTimeValid(candidate.last_update_time))
    {
        return true;
    }

    const double age_s =
        DiffSeconds(now, candidate.creation_time);

    const double idle_s =
        DiffSeconds(now, candidate.last_update_time);

    if (age_s < 0.0 || idle_s < 0.0)
        return true;

    if (candidate.HasCedData() || IsValidTimingPair(candidate))
        return age_s > COMPLETE_LIFETIME_S;

    return idle_s > PARTIAL_TIMEOUT_S;
}

void GalileoNavCandidateStore::StoreWord(GalileoNavCandidate& candidate,
    const GalileoInavPageParts& page,
    int32_t wt)
{
    if (wt < 0 || wt > GAL_MAX_WT)
        return;

    GalileoNavWord& word = candidate.words[wt];

    word = GalileoNavWord{};

    word.wt = wt;
    word.page_epoch = page.page_epoch;
    word.has_epoch = true;
    word.valid = true;

    std::memcpy(word.even.data(), page.even, GAL_INAV_BYTES);
    std::memcpy(word.odd.data(), page.odd, GAL_INAV_BYTES);

    static int32_t nav_store_debug_count = 0;

    if (nav_store_debug_count < 80)
    {
        const bool has_ced_now =
            candidate.HasWord(GAL_WT1) &&
            candidate.HasWord(GAL_WT2) &&
            candidate.HasWord(GAL_WT3) &&
            candidate.HasWord(GAL_WT4) &&
            candidate.HasWord(GAL_WT5);

        const bool has_timing_now =
            candidate.HasWord(GAL_WT6) &&
            candidate.HasWord(GAL_WT10);

        printf("NAVDATA stored: prn=%d iod=%d toe=%d wt=%d wn=%d tow=%.0f has_ced=%d has_timing=%d\n",
            candidate.prn,
            candidate.iod,
            candidate.toe,
            wt,
            page.page_epoch.wn,
            page.page_epoch.tow,
            has_ced_now ? 1 : 0,
            has_timing_now ? 1 : 0);

        ++nav_store_debug_count;
    }
}

void GalileoNavCandidateStore::ClearWord(GalileoNavCandidate& candidate,
    int32_t wt)
{
    if (wt < 0 || wt > GAL_MAX_WT)
        return;

    candidate.words[wt] = GalileoNavWord{};
}

bool GalileoNavCandidateStore::IsValidTimingPair(const GalileoNavCandidate& candidate)
{
    if (!candidate.HasWord(GAL_WT6) ||
        !candidate.HasWord(GAL_WT10))
    {
        return false;
    }

    const GalileoNavWord& wt6 = candidate.words[GAL_WT6];
    const GalileoNavWord& wt10 = candidate.words[GAL_WT10];

    if (!wt6.has_epoch || !wt10.has_epoch)
        return false;

    if (!IsTimeValid(wt6.page_epoch) ||
        !IsTimeValid(wt10.page_epoch))
    {
        return false;
    }

    const double dt_s =
        DiffSeconds(wt10.page_epoch, wt6.page_epoch);

    if (dt_s < 0.0 || dt_s > TIMING_PAIR_MAX_SPAN_S)
        return false;

    return true;
}
