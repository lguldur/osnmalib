#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <limits>
#include <tuple>

#include "galileo_inav_page_parts.h"
#include "gnss_time.h"
#include "osnma_mack.h"
#include "osnma_types.h"

static constexpr int32_t GAL_WT1 = 1;
static constexpr int32_t GAL_WT2 = 2;
static constexpr int32_t GAL_WT3 = 3;
static constexpr int32_t GAL_WT4 = 4;
static constexpr int32_t GAL_WT5 = 5;
static constexpr int32_t GAL_WT6 = 6;
static constexpr int32_t GAL_WT10 = 10;

static constexpr int32_t GAL_MAX_WT = 10;

struct GalileoNavWord
{
    int32_t wt = 0;

    GnssTime page_epoch{};
    bool has_epoch = false;

    std::array<std::uint8_t, GAL_INAV_BYTES> even{};
    std::array<std::uint8_t, GAL_INAV_BYTES> odd{};

    bool valid = false;
};

struct GalileoNavCandidate
{
    int32_t prn = -1;
    int32_t iod = -1;
    int32_t toe = -1;

    GnssTime creation_time{};
    GnssTime last_update_time{};

    bool complete = false;

    /*
        Daniel-Estevez-style rolling CED age, in 30 s subframes.

        For ADKD=0/12, the CED state is copied from one subframe to the
        next. Each WT1..WT5 range carries its own age. A word received in
        the current subframe has age 0; a copied word from the previous
        subframe has age 1, etc. COP is checked by the verifier as:

            max_word_age + 1 <= COP
    */
    static constexpr int32_t INVALID_WORD_AGE = std::numeric_limits<int32_t>::max();
    std::array<int32_t, GAL_MAX_WT + 1> word_age{};

    std::array<GalileoNavWord, GAL_MAX_WT + 1> words{};

    bool HasWord(int32_t wt) const;
    bool HasCedData() const;
    bool HasTimingData() const;
    bool IsComplete() const;
    int32_t MaxCedWordAge() const;
    bool IsCedCopEligible(int32_t cop) const;

    int32_t MaxTimingWordAge() const;
    bool IsTimingCopEligible(int32_t cop) const;
};

class GalileoNavCandidateStore
{
public:
    void Reset();

    void SetNavTimingMode(NavTimingMode mode);
    NavTimingMode GetNavTimingMode() const;

    bool FeedPage(const GalileoInavPageParts& page,
        AuthReason& reason_out);

    void Cleanup(const GnssTime& now);

    const GalileoNavCandidate* FindComplete(int32_t prn,
        int32_t iod,
        const GnssTime& now,
        int32_t cop) const;

    const GalileoNavCandidate* FindForAdkd(int32_t prn,
        OsnmaAdkd adkd,
        const GnssTime& now,
        int32_t cop) const;

private:
    struct PageHeader
    {
        int32_t wt = -1;
        int32_t iod = -1;
        int32_t toe = -1;
        bool valid = false;
    };

private:
    using Key = std::tuple<int32_t, int32_t, int32_t>;

    static constexpr double PARTIAL_TIMEOUT_S = 240.0;
    static constexpr double COMPLETE_LIFETIME_S = 1200.0;

    // WT6-anchored ADKD=4 timing pair guard.
    // This is intentionally conservative and prevents mixing unrelated WT6/WT10.
    static constexpr double TIMING_PAIR_MAX_SPAN_S = 240.0;

private:
    std::map<Key, GalileoNavCandidate> candidates_;
    NavTimingMode timing_mode_ = NavTimingMode::Standard;

private:
    static PageHeader ExtractPageHeader(const GalileoInavPageParts& page);

    GnssTime MakeSubframeTimeForPageEpoch(const GnssTime& time) const;

    GnssTime MakeSubframeTimeForRequest(const GnssTime& time) const;

    static Key MakeCedKeyFromSubframeTime(int32_t prn,
        const GnssTime& subframe_time);

    static Key MakeTimingKey(int32_t prn);

    static bool IsSupportedWordType(int32_t wt);

    static bool CanAcceptCedWord(const GalileoNavCandidate& candidate,
        int32_t wt);

    static bool IsExpired(const GalileoNavCandidate& candidate,
        const GnssTime& now);

    void StoreWord(GalileoNavCandidate& candidate,
        const GalileoInavPageParts& page,
        int32_t wt) const;

    static void ClearWord(GalileoNavCandidate& candidate,
        int32_t wt);

    GalileoNavCandidate MakeRollingCedCandidate(int32_t prn,
        const PageHeader& header,
        const GnssTime& subframe_time,
        const GnssTime& page_epoch) const;

    const GalileoNavCandidate* FindNewestCedBefore(int32_t prn,
        const GnssTime& subframe_time) const;

    static int32_t SubframeDistance30s(const GnssTime& newer,
        const GnssTime& older);

    static void InitializeWordAges(GalileoNavCandidate& candidate);

    static void IncreaseCedWordAges(GalileoNavCandidate& candidate,
        int32_t subframe_steps);

    static void IncreaseTimingWordAges(GalileoNavCandidate& candidate,
        int32_t subframe_steps);

    static bool IsValidTimingPair(const GalileoNavCandidate& candidate);

    bool FeedCedPage(const GalileoInavPageParts& page,
        const PageHeader& header,
        AuthReason& reason_out);

    bool FeedTimingPage(const GalileoInavPageParts& page,
        const PageHeader& header,
        AuthReason& reason_out);
};
