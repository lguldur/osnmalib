#include "galileo_nav_candidate.h"

#include <cstdio>
#include <cstring>

#include "osnma_bit_utils.h"

#ifndef OSNMA_VERBOSE_NAVDATA
#define OSNMA_VERBOSE_NAVDATA 0
#endif

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

int32_t GalileoNavCandidate::MaxCedWordAge() const
{
    if (!HasCedData())
        return INVALID_WORD_AGE;

    int32_t max_age = 0;

    for (int32_t wt = GAL_WT1; wt <= GAL_WT5; ++wt)
    {
        if (word_age[wt] == INVALID_WORD_AGE)
            return INVALID_WORD_AGE;

        if (word_age[wt] > max_age)
            max_age = word_age[wt];
    }

    return max_age;
}

bool GalileoNavCandidate::IsCedCopEligible(int32_t cop) const
{
    if (cop <= 0)
        return false;

    const int32_t max_age = MaxCedWordAge();

    if (max_age == INVALID_WORD_AGE)
        return false;

    /*
        Daniel Estevez's check is:

            max_age().saturating_add(1) <= COP

        Ages are in 30 s subframes.
    */
    return (max_age + 1) <= cop;
}

void GalileoNavCandidateStore::Reset()
{
    candidates_.clear();
}

void GalileoNavCandidateStore::SetNavTimingMode(NavTimingMode mode)
{
    timing_mode_ = mode;
}

NavTimingMode GalileoNavCandidateStore::GetNavTimingMode() const
{
    return timing_mode_;
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
    /*
        ADKD=0/12 CED is assembled per PRN and 30-second I/NAV
        subframe, following public OSNMA implementations.

        Do not group by parsed IODnav/TOE here. The authenticated CED
        message is the concatenation of WT1..WT5 authenticated bit ranges
        from the same I/NAV subframe. Parsing IODnav from a fixed bit offset
        in every word was wrong and prevented WT2..WT5 from joining WT1.
    */
    const GnssTime subframe_time =
        MakeSubframeTimeForPageEpoch(page.page_epoch);

    const Key key =
        MakeCedKeyFromSubframeTime(page.prn,
            subframe_time);

    auto it = candidates_.find(key);

    if (it == candidates_.end())
    {
        GalileoNavCandidate candidate =
            MakeRollingCedCandidate(page.prn,
                header,
                subframe_time,
                page.page_epoch);

        StoreWord(candidate, page, header.wt);

        candidate.complete = candidate.IsComplete();

        candidates_[key] = candidate;

        reason_out = AuthReason::None;
        return true;
    }

    GalileoNavCandidate& candidate = it->second;

    if (candidate.HasWord(header.wt))
    {
        /*
            A repeated WT in the same 30 s subframe replaces the previous
            copy. This is safer than rejecting the whole candidate, and it
            avoids stale partial candidates when a receiver provides repeated
            or corrected pages.
        */
        ClearWord(candidate,
            header.wt);
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
    const Key key = MakeTimingKey(page.prn);

    auto it = candidates_.find(key);

    if (it == candidates_.end())
    {
        GalileoNavCandidate candidate{};
        InitializeWordAges(candidate);
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
    const GnssTime& now,
    int32_t cop) const
{
    (void)iod;

    if (prn <= 0)
        return nullptr;

    if (!IsTimeValid(now))
        return nullptr;

    /*
        Daniel-like ADKD=0/12 lookup.

        'now' is already the requested CED/status subframe time, typically
        MACK GST - 30 s. Look up the exact rolling CED state for that
        subframe. Do not replace it with a whole older CED candidate: the
        rolling candidate already contains word-by-word copied data plus
        per-word ages.

        COP is not a TESLA key delay. It is a maximum CED age rule:

            max(WT1..WT5 ages) + 1 <= COP
    */
    const GnssTime subframe_time =
        MakeSubframeTimeForRequest(now);

    const Key exact_key =
        MakeCedKeyFromSubframeTime(prn,
            subframe_time);

    auto exact_it = candidates_.find(exact_key);

    if (exact_it == candidates_.end())
    {
#if OSNMA_VERBOSE_NAVDATA
        static int32_t find_missing_debug_count = 0;

        if (find_missing_debug_count < 120)
        {
            printf("NAVDATA find failed: prn=%d wn=%d tow=%.0f subframe_tow=%.0f reason=no exact rolling candidate. same_prn_candidates=",
                prn,
                now.wn,
                now.tow,
                subframe_time.tow);

            int32_t printed = 0;

            for (const auto& kv : candidates_)
            {
                const Key& candidate_key = kv.first;

                const int32_t cand_prn = std::get<0>(candidate_key);
                const int32_t cand_wn = std::get<1>(candidate_key);
                const int32_t cand_tow = std::get<2>(candidate_key);

                if (cand_prn == prn && printed < 16)
                {
                    const GalileoNavCandidate& c = kv.second;

                    printf(" [%d/%d ced=%d max_age=%d w1=%d/%d w2=%d/%d w3=%d/%d w4=%d/%d w5=%d/%d]",
                        cand_wn,
                        cand_tow,
                        c.HasCedData() ? 1 : 0,
                        c.MaxCedWordAge(),
                        c.HasWord(GAL_WT1) ? 1 : 0, c.word_age[GAL_WT1],
                        c.HasWord(GAL_WT2) ? 1 : 0, c.word_age[GAL_WT2],
                        c.HasWord(GAL_WT3) ? 1 : 0, c.word_age[GAL_WT3],
                        c.HasWord(GAL_WT4) ? 1 : 0, c.word_age[GAL_WT4],
                        c.HasWord(GAL_WT5) ? 1 : 0, c.word_age[GAL_WT5]);

                    ++printed;
                }
            }

            printf("\n");
            ++find_missing_debug_count;
        }
#endif

        return nullptr;
    }

    const GalileoNavCandidate& candidate = exact_it->second;

    if (IsExpired(candidate, now))
    {
#if OSNMA_VERBOSE_NAVDATA
        static int32_t find_expired_debug_count = 0;

        if (find_expired_debug_count < 40)
        {
            printf("NAVDATA find exact expired: prn=%d wn=%d tow=%.0f subframe_tow=%.0f creation_tow=%.0f last_tow=%.0f\n",
                prn,
                now.wn,
                now.tow,
                subframe_time.tow,
                candidate.creation_time.tow,
                candidate.last_update_time.tow);

            ++find_expired_debug_count;
        }
#endif

        return nullptr;
    }

    if (!candidate.HasCedData())
    {
#if OSNMA_VERBOSE_NAVDATA
        static int32_t find_incomplete_debug_count = 0;

        if (find_incomplete_debug_count < 120)
        {
            printf("NAVDATA find exact incomplete: prn=%d wn=%d tow=%.0f subframe_tow=%.0f w1=%d/%d w2=%d/%d w3=%d/%d w4=%d/%d w5=%d/%d\n",
                prn,
                now.wn,
                now.tow,
                subframe_time.tow,
                candidate.HasWord(GAL_WT1) ? 1 : 0, candidate.word_age[GAL_WT1],
                candidate.HasWord(GAL_WT2) ? 1 : 0, candidate.word_age[GAL_WT2],
                candidate.HasWord(GAL_WT3) ? 1 : 0, candidate.word_age[GAL_WT3],
                candidate.HasWord(GAL_WT4) ? 1 : 0, candidate.word_age[GAL_WT4],
                candidate.HasWord(GAL_WT5) ? 1 : 0, candidate.word_age[GAL_WT5]);

            ++find_incomplete_debug_count;
        }
#endif

        return nullptr;
    }

    if (!candidate.IsCedCopEligible(cop))
    {
#if OSNMA_VERBOSE_NAVDATA
        static int32_t find_cop_debug_count = 0;

        if (find_cop_debug_count < 120)
        {
            printf("NAVDATA find exact COP reject: prn=%d wn=%d tow=%.0f subframe_tow=%.0f cop=%d max_age=%d w1=%d w2=%d w3=%d w4=%d w5=%d\n",
                prn,
                now.wn,
                now.tow,
                subframe_time.tow,
                cop,
                candidate.MaxCedWordAge(),
                candidate.word_age[GAL_WT1],
                candidate.word_age[GAL_WT2],
                candidate.word_age[GAL_WT3],
                candidate.word_age[GAL_WT4],
                candidate.word_age[GAL_WT5]);

            ++find_cop_debug_count;
        }
#endif

        return nullptr;
    }


    return &candidate;
}

const GalileoNavCandidate*
GalileoNavCandidateStore::FindForAdkd(int32_t prn,
    OsnmaAdkd adkd,
    const GnssTime& now,
    int32_t cop) const
{
    if (adkd == OsnmaAdkd::InavCed ||
        adkd == OsnmaAdkd::SlowMac)
    {
        return FindComplete(prn, -1, now, cop);
    }

    if (adkd == OsnmaAdkd::InavTiming)
    {
        const Key key = MakeTimingKey(prn);

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

GnssTime GalileoNavCandidateStore::MakeSubframeTimeForPageEpoch(const GnssTime& time) const
{
    GnssTime out = time;

    if (!IsTimeValid(out))
        return out;

    double ref_tow = out.tow;

    if (timing_mode_ == NavTimingMode::OfficialCsvE1B)
        ref_tow -= 1.0;

    while (ref_tow < 0.0)
    {
        ref_tow += 604800.0;
        --out.wn;
    }

    while (ref_tow >= 604800.0)
    {
        ref_tow -= 604800.0;
        ++out.wn;
    }

    const int32_t tow_s =
        static_cast<int32_t>(ref_tow);

    out.tow = static_cast<double>((tow_s / 30) * 30);
    return out;
}

GnssTime GalileoNavCandidateStore::MakeSubframeTimeForRequest(const GnssTime& time) const
{
    GnssTime out = time;

    if (!IsTimeValid(out))
        return out;

    const int32_t tow_s =
        static_cast<int32_t>(out.tow);

    out.tow = static_cast<double>((tow_s / 30) * 30);
    return out;
}

GalileoNavCandidateStore::Key
GalileoNavCandidateStore::MakeCedKeyFromSubframeTime(int32_t prn,
    const GnssTime& subframe_time)
{
    return Key(prn,
        subframe_time.wn,
        static_cast<int32_t>(subframe_time.tow));
}

GalileoNavCandidateStore::Key
GalileoNavCandidateStore::MakeTimingKey(int32_t prn)
{
    return Key(prn,
        -1,
        -1);
}

bool GalileoNavCandidateStore::IsSupportedWordType(int32_t wt)
{
    return (wt >= GAL_WT1 && wt <= GAL_WT6) ||
        (wt == GAL_WT10);
}

bool GalileoNavCandidateStore::CanAcceptCedWord(const GalileoNavCandidate& candidate,
    int32_t wt)
{
    (void)candidate;
    return wt >= GAL_WT1 && wt <= GAL_WT5;
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

    /*
        The input stream is not strictly monotonic at page level.

        Example seen in the logs:
            words around TOW 150/172/174 are stored,
            then words around TOW 120 arrive afterwards.

        The old code treated negative age/idle as expired and deleted the
        candidates that were merely ahead of the current page timestamp.
        That made later ADKD0 lookups print:
            same_prn_candidates=
        even though complete CED candidates had already been stored.

        If 'now' is earlier than the candidate time, do not expire it.
        It will be considered again when the stream catches up.
    */
    if (age_s < 0.0 || idle_s < 0.0)
        return false;

    if (candidate.HasCedData() || IsValidTimingPair(candidate))
        return age_s > COMPLETE_LIFETIME_S;

    return idle_s > PARTIAL_TIMEOUT_S;
}

void GalileoNavCandidateStore::StoreWord(GalileoNavCandidate& candidate,
    const GalileoInavPageParts& page,
    int32_t wt) const
{
    if (wt < 0 || wt > GAL_MAX_WT)
        return;

    GalileoNavWord& word = candidate.words[wt];

    word = GalileoNavWord{};

    word.wt = wt;
    word.page_epoch = page.page_epoch;
    word.has_epoch = true;
    word.valid = true;
    candidate.word_age[wt] = 0;

    std::memcpy(word.even.data(), page.even, GAL_INAV_BYTES);
    std::memcpy(word.odd.data(), page.odd, GAL_INAV_BYTES);

#if OSNMA_VERBOSE_NAVDATA
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

        const GnssTime subframe_time =
            MakeSubframeTimeForPageEpoch(page.page_epoch);

        printf("NAVDATA stored: prn=%d iod=%d toe=%d wt=%d wn=%d tow=%.0f subframe_tow=%.0f has_ced=%d has_timing=%d max_age=%d\n",
            candidate.prn,
            candidate.iod,
            candidate.toe,
            wt,
            page.page_epoch.wn,
            page.page_epoch.tow,
            subframe_time.tow,
            has_ced_now ? 1 : 0,
            has_timing_now ? 1 : 0,
            candidate.MaxCedWordAge());

        ++nav_store_debug_count;
    }
#endif
}

void GalileoNavCandidateStore::ClearWord(GalileoNavCandidate& candidate,
    int32_t wt)
{
    if (wt < 0 || wt > GAL_MAX_WT)
        return;

    candidate.words[wt] = GalileoNavWord{};
    candidate.word_age[wt] = GalileoNavCandidate::INVALID_WORD_AGE;
}

GalileoNavCandidate GalileoNavCandidateStore::MakeRollingCedCandidate(int32_t prn,
    const PageHeader& header,
    const GnssTime& subframe_time,
    const GnssTime& page_epoch) const
{
    GalileoNavCandidate candidate{};
    InitializeWordAges(candidate);

    const GalileoNavCandidate* previous =
        FindNewestCedBefore(prn,
            subframe_time);

    if (previous != nullptr)
    {
        candidate = *previous;

        const int32_t steps =
            SubframeDistance30s(subframe_time,
                previous->creation_time);

        IncreaseCedWordAges(candidate,
            steps > 0 ? steps : 1);
    }

    candidate.prn = prn;
    candidate.iod = header.iod;
    candidate.toe = header.toe;
    candidate.creation_time = subframe_time;
    candidate.last_update_time = page_epoch;
    candidate.complete = candidate.IsComplete();

    return candidate;
}

const GalileoNavCandidate* GalileoNavCandidateStore::FindNewestCedBefore(int32_t prn,
    const GnssTime& subframe_time) const
{
    const GalileoNavCandidate* best = nullptr;
    double best_age_s = 0.0;

    for (const auto& kv : candidates_)
    {
        const Key& candidate_key = kv.first;

        if (std::get<0>(candidate_key) != prn)
            continue;

        const int32_t candidate_wn = std::get<1>(candidate_key);
        const int32_t candidate_tow = std::get<2>(candidate_key);

        if (candidate_wn < 0 || candidate_tow < 0)
            continue;

        const GalileoNavCandidate& candidate = kv.second;

        GnssTime candidate_time = subframe_time;
        candidate_time.wn = candidate_wn;
        candidate_time.tow = static_cast<double>(candidate_tow);

        const double age_s =
            DiffSeconds(subframe_time,
                candidate_time);

        if (age_s <= 0.0)
            continue;

        if (best == nullptr || age_s < best_age_s)
        {
            best = &candidate;
            best_age_s = age_s;
        }
    }

    return best;
}

int32_t GalileoNavCandidateStore::SubframeDistance30s(const GnssTime& newer,
    const GnssTime& older)
{
    const double dt_s = DiffSeconds(newer, older);

    if (dt_s <= 0.0)
        return 0;

    return static_cast<int32_t>(dt_s / 30.0 + 0.5);
}

void GalileoNavCandidateStore::InitializeWordAges(GalileoNavCandidate& candidate)
{
    for (int32_t i = 0; i <= GAL_MAX_WT; ++i)
        candidate.word_age[i] = GalileoNavCandidate::INVALID_WORD_AGE;
}

void GalileoNavCandidateStore::IncreaseCedWordAges(GalileoNavCandidate& candidate,
    int32_t subframe_steps)
{
    if (subframe_steps <= 0)
        return;

    for (int32_t wt = GAL_WT1; wt <= GAL_WT5; ++wt)
    {
        if (!candidate.HasWord(wt))
        {
            candidate.word_age[wt] = GalileoNavCandidate::INVALID_WORD_AGE;
            continue;
        }

        if (candidate.word_age[wt] == GalileoNavCandidate::INVALID_WORD_AGE)
            continue;

        if (candidate.word_age[wt] > 1000000)
            continue;

        candidate.word_age[wt] += subframe_steps;
    }
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
