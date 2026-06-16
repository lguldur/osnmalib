#pragma once

#include <array>
#include <cstdint>
#include <map>
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

    std::array<GalileoNavWord, GAL_MAX_WT + 1> words{};

    bool HasWord(int32_t wt) const;
    bool HasCedData() const;
    bool HasTimingData() const;
    bool IsComplete() const;
};

class GalileoNavCandidateStore
{
public:
    void Reset();

    bool FeedPage(const GalileoInavPageParts& page,
        AuthReason& reason_out);

    void Cleanup(const GnssTime& now);

    const GalileoNavCandidate* FindComplete(int32_t prn,
        int32_t iod,
        const GnssTime& now) const;

    const GalileoNavCandidate* FindForAdkd(int32_t prn,
        OsnmaAdkd adkd,
        const GnssTime& now) const;

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
    static constexpr double COMPLETE_LIFETIME_S = 172800.0;

    // WT6-anchored ADKD=4 timing pair guard.
    // This is intentionally conservative and prevents mixing unrelated WT6/WT10.
    static constexpr double TIMING_PAIR_MAX_SPAN_S = 240.0;

private:
    std::map<Key, GalileoNavCandidate> candidates_;

private:
    static PageHeader ExtractPageHeader(const GalileoInavPageParts& page);

    static GnssTime MakeSubframeTime(const GnssTime& time);

    static Key MakeCedKey(int32_t prn,
        const GnssTime& time);

    static Key MakeTimingKey(int32_t prn);

    static bool IsSupportedWordType(int32_t wt);

    static bool CanAcceptCedWord(const GalileoNavCandidate& candidate,
        int32_t wt);

    static bool IsExpired(const GalileoNavCandidate& candidate,
        const GnssTime& now);

    static void StoreWord(GalileoNavCandidate& candidate,
        const GalileoInavPageParts& page,
        int32_t wt);

    static void ClearWord(GalileoNavCandidate& candidate,
        int32_t wt);

    static bool IsValidTimingPair(const GalileoNavCandidate& candidate);

    bool FeedCedPage(const GalileoInavPageParts& page,
        const PageHeader& header,
        AuthReason& reason_out);

    bool FeedTimingPage(const GalileoInavPageParts& page,
        const PageHeader& header,
        AuthReason& reason_out);
};
