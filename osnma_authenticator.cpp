#include "osnma_authenticator.h"

void OsnmaAuthenticator::Reset()
{
    for (auto& s : sats_)
        s = SatRecord{};

    assembler_.Reset();
    engine_.Reset();
}

bool OsnmaAuthenticator::IsValidPrn(int32_t prn) const
{
    return prn > 0 && prn < MAX_PRN;
}

FeedResult OsnmaAuthenticator::FeedRawInavPage(int32_t prn,
    const std::uint8_t* even_128b,
    const std::uint8_t* odd_128b,
    const GnssTime& page_time,
    NavSignalSource source,
    int32_t raw_source,
    bool crc_ok)
{
    GalileoInavPageParts page{};

    page.prn = prn;
    page.page_epoch = page_time;
    page.crc_ok = crc_ok;
    page.source = source;
    page.native_source_code = raw_source;
    page.even = even_128b;
    page.odd = odd_128b;

    return FeedPageParts(page);
}

FeedResult OsnmaAuthenticator::FeedPageParts(const GalileoInavPageParts& page)
{
    FeedResult out{};
    out.prn = page.prn;

    if (!IsValidPrn(page.prn))
    {
        out.status.reason = AuthReason::InvalidPrn;
        return out;
    }

    auto& rec = sats_[page.prn];

    rec.state = AuthState::Unknown;
    rec.reason = AuthReason::NoOsnmaData;
    rec.last_time = page.page_epoch;
    rec.has_time = true;
    rec.source = page.source;
    rec.raw_source = page.native_source_code;

    AuthReason nav_reason = AuthReason::None;
    (void)engine_.FeedNavigationPage(page, nav_reason);

    ParsedPage parsed{};
    AuthReason parse_reason = AuthReason::None;

    const bool parsed_ok =
        parser_.Parse(page, parsed, parse_reason);

    rec.reason = parse_reason;

    if (parsed_ok)
    {
        OsnmaSubframe subframe{};
        AuthReason asm_reason = AuthReason::None;

        const bool subframe_complete =
            assembler_.FeedParsedPage(parsed, subframe, asm_reason);

        rec.reason = asm_reason;

        if (subframe_complete)
        {
            const OsnmaEngine::Result engine_result =
                engine_.ProcessSubframe(subframe,
                    page.source,
                    page.native_source_code);

            rec.state = engine_result.state;
            rec.reason = engine_result.reason;
        }
        else
        {
            rec.state = AuthState::Unknown;
        }
    }

    out.status = GetStatus(page.prn, page.page_epoch);
    return out;
}

Status OsnmaAuthenticator::GetStatus(int32_t prn, const GnssTime& now) const
{
    Status s{};

    if (!IsValidPrn(prn))
    {
        s.reason = AuthReason::InvalidPrn;
        return s;
    }

    const auto& rec = sats_[prn];

    s.state = rec.state;
    s.reason = rec.reason;
    s.event_time = rec.last_time;
    s.source = rec.source;
    s.native_source_code = rec.raw_source;

    if (rec.has_time)
        s.age_s = DiffSeconds(now, rec.last_time);

    s.valid = rec.has_time;

    return s;
}

const OsnmaEngine::Statistics& OsnmaAuthenticator::GetEngineStatistics() const
{
    return engine_.GetStatistics();
}

bool OsnmaAuthenticator::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return engine_.SetMerkleRoot(root_32_bytes);
}
