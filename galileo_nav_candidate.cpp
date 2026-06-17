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
        GalileoNavCandidate candidate{};
        candidate.prn = page.prn;
        candidate.iod = header.iod;
        candidate.toe = header.toe;
        candidate.creation_time = subframe_time;
        candidate.last_update_time = page.page_epoch;

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
    (void)iod;

    if (prn <= 0)
        return nullptr;

    if (!IsTimeValid(now))
        return nullptr;

    /*
        For ADKD=0/12, 'now' is the requested CED subframe time.

        First try the exact PRN + 30 s subframe candidate. If it is missing
        or incomplete, use the newest previous complete CED for the same PRN.

        This mirrors the useful behavior of Daniel Estevez's circular-buffer
        nav-message store: previously decoded CED remains available for later
        subframes and is selected according to age/COP by the caller.
    */
    const GnssTime subframe_time =
        MakeSubframeTimeForRequest(now);

    const Key exact_key =
        MakeCedKeyFromSubframeTime(prn,
            subframe_time);

    auto exact_it = candidates_.find(exact_key);

    if (exact_it != candidates_.end())
    {
        const GalileoNavCandidate& exact_candidate =
            exact_it->second;

        if (exact_candidate.HasCedData() &&
            !IsExpired(exact_candidate, now))
        {
            return &exact_candidate;
        }

        if (!exact_candidate.HasCedData())
        {
            static int32_t find_incomplete_debug_count = 0;

            if (find_incomplete_debug_count < 80)
            {
                printf("NAVDATA find exact incomplete: prn=%d wn=%d tow=%.0f subframe_tow=%.0f w1=%d w2=%d w3=%d w4=%d w5=%d\n",
                    prn,
                    now.wn,
                    now.tow,
                    subframe_time.tow,
                    exact_candidate.HasWord(GAL_WT1) ? 1 : 0,
                    exact_candidate.HasWord(GAL_WT2) ? 1 : 0,
                    exact_candidate.HasWord(GAL_WT3) ? 1 : 0,
                    exact_candidate.HasWord(GAL_WT4) ? 1 : 0,
                    exact_candidate.HasWord(GAL_WT5) ? 1 : 0);

                ++find_incomplete_debug_count;
            }
        }
        else
        {
            static int32_t find_expired_debug_count = 0;

            if (find_expired_debug_count < 40)
            {
                printf("NAVDATA find exact expired: prn=%d wn=%d tow=%.0f subframe_tow=%.0f creation_tow=%.0f last_tow=%.0f\n",
                    prn,
                    now.wn,
                    now.tow,
                    subframe_time.tow,
                    exact_candidate.creation_time.tow,
                    exact_candidate.last_update_time.tow);

                ++find_expired_debug_count;
            }
        }

        /*
            Important: if the requested subframe candidate exists but is not
            usable, do not fall back to an older CED candidate.  Falling back
            converts a temporary/structural missing-WT condition into a hard
            MAC failure with stale navdata, which hides the real problem.

            If no candidate exists at all for the requested subframe, the code
            below still allows the Daniel-style previous-complete fallback.
        */
        return nullptr;
    }

    const GalileoNavCandidate* best_candidate = nullptr;
    int32_t best_wn = 0;
    int32_t best_tow = 0;
    double best_age_s = 0.0;

    static constexpr double MAX_CED_FALLBACK_AGE_S = 60.0;

    for (const auto& kv : candidates_)
    {
        const Key& candidate_key =
            kv.first;

        const int32_t candidate_prn =
            std::get<0>(candidate_key);

        if (candidate_prn != prn)
            continue;

        const int32_t candidate_wn =
            std::get<1>(candidate_key);

        const int32_t candidate_tow =
            std::get<2>(candidate_key);

        if (candidate_wn < 0 || candidate_tow < 0)
            continue;

        const GalileoNavCandidate& candidate =
            kv.second;

        if (!candidate.HasCedData())
            continue;

        if (IsExpired(candidate, now))
            continue;

        GnssTime candidate_time = subframe_time;
        candidate_time.wn = candidate_wn;
        candidate_time.tow = static_cast<double>(candidate_tow);

        const double age_s =
            DiffSeconds(subframe_time, candidate_time);

        if (age_s < 0.0)
            continue;

        if (age_s > MAX_CED_FALLBACK_AGE_S)
            continue;

        if (best_candidate == nullptr || age_s < best_age_s)
        {
            best_candidate = &candidate;
            best_wn = candidate_wn;
            best_tow = candidate_tow;
            best_age_s = age_s;
        }
    }

    if (best_candidate != nullptr)
    {
        static int32_t find_fallback_debug_count = 0;

        if (find_fallback_debug_count < 120)
        {
            printf("NAVDATA find fallback: prn=%d requested_wn=%d requested_tow=%.0f selected_wn=%d selected_tow=%d age_s=%.0f\n",
                prn,
                subframe_time.wn,
                subframe_time.tow,
                best_wn,
                best_tow,
                best_age_s);

            ++find_fallback_debug_count;
        }

        return best_candidate;
    }

    static int32_t find_missing_debug_count = 0;

    if (find_missing_debug_count < 120)
    {
        printf("NAVDATA find failed: prn=%d wn=%d tow=%.0f subframe_tow=%.0f reason=no usable candidate. same_prn_candidates=",
            prn,
            now.wn,
            now.tow,
            subframe_time.tow);

        int32_t printed = 0;

        for (const auto& kv : candidates_)
        {
            const Key& candidate_key = kv.first;

            const int32_t cand_prn =
                std::get<0>(candidate_key);

            const int32_t cand_wn =
                std::get<1>(candidate_key);

            const int32_t cand_tow =
                std::get<2>(candidate_key);

            if (cand_prn == prn && printed < 16)
            {
                const GalileoNavCandidate& c =
                    kv.second;

                printf(" [%d/%d ced=%d w1=%d w2=%d w3=%d w4=%d w5=%d]",
                    cand_wn,
                    cand_tow,
                    c.HasCedData() ? 1 : 0,
                    c.HasWord(GAL_WT1) ? 1 : 0,
                    c.HasWord(GAL_WT2) ? 1 : 0,
                    c.HasWord(GAL_WT3) ? 1 : 0,
                    c.HasWord(GAL_WT4) ? 1 : 0,
                    c.HasWord(GAL_WT5) ? 1 : 0);

                ++printed;
            }
        }

        printf("\n");

        ++find_missing_debug_count;
    }

    return nullptr;
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

        const GnssTime subframe_time =
            MakeSubframeTimeForPageEpoch(page.page_epoch);

        printf("NAVDATA stored: prn=%d iod=%d toe=%d wt=%d wn=%d tow=%.0f subframe_tow=%.0f has_ced=%d has_timing=%d\n",
            candidate.prn,
            candidate.iod,
            candidate.toe,
            wt,
            page.page_epoch.wn,
            page.page_epoch.tow,
            subframe_time.tow,
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
