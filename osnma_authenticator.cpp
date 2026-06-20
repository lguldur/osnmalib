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

void OsnmaAuthenticator::SetNavTimingMode(NavTimingMode mode)
{
    assembler_.SetNavTimingMode(mode);
    engine_.SetNavTimingMode(mode);
}

NavTimingMode OsnmaAuthenticator::GetNavTimingMode() const
{
    return engine_.GetNavTimingMode();
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

            if (asm_reason != AuthReason::WaitingForMoreFrames &&
                asm_reason != AuthReason::WaitingForKey &&
                asm_reason != AuthReason::None)
            {
                PegasusLogRow log{};
                if (IsTimeValid(page.page_epoch))
                {
                    log.rx_week = page.page_epoch.wn + GALILEO_GST_TO_GPS_WEEK_OFFSET;
                    log.rx_tom = page.page_epoch.tow;
                }
                log.prn = page.prn;
                log.severity = PegasusLogSeverity::Warning;
                log.event = PegasusLogEvent::SubframeAssemblyFailed;
                log.auth_reason = asm_reason;
                log.source = page.source;
                log.raw_source = page.native_source_code;
                log.detail = "OSNMA subframe assembly failed";
                engine_.AddPegasusLogRow(log);
            }
        }
    }
    else if (parse_reason == AuthReason::InvalidFrameFormat ||
             parse_reason == AuthReason::InvalidTime ||
             parse_reason == AuthReason::BufferOverflow ||
             parse_reason == AuthReason::InternalError)
    {
        PegasusLogRow log{};
        if (IsTimeValid(page.page_epoch))
        {
            log.rx_week = page.page_epoch.wn + GALILEO_GST_TO_GPS_WEEK_OFFSET;
            log.rx_tom = page.page_epoch.tow;
        }
        log.prn = page.prn;
        log.severity = PegasusLogSeverity::Warning;
        log.event = PegasusLogEvent::PageParseFailed;
        log.auth_reason = parse_reason;
        log.source = page.source;
        log.raw_source = page.native_source_code;
        log.detail = "OSNMA reserved-field/page parsing failed";
        engine_.AddPegasusLogRow(log);
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

bool OsnmaAuthenticator::PopAuthenticatedCedStatus(
    GalileoAuthenticatedCedStatus& data)
{
    return engine_.PopAuthenticatedCedStatus(data);
}

bool OsnmaAuthenticator::PopAuthenticatedTiming(
    GalileoAuthenticatedTiming& data)
{
    return engine_.PopAuthenticatedTiming(data);
}

int32_t OsnmaAuthenticator::AuthenticatedCedStatusCount() const
{
    return engine_.AuthenticatedCedStatusCount();
}

int32_t OsnmaAuthenticator::AuthenticatedTimingCount() const
{
    return engine_.AuthenticatedTimingCount();
}


bool OsnmaAuthenticator::PopPegasusEphRow(PegasusEphRow& row)
{
    return engine_.PopPegasusEphRow(row);
}

bool OsnmaAuthenticator::PopPegasusIonoRow(PegasusIonoRow& row)
{
    return engine_.PopPegasusIonoRow(row);
}

bool OsnmaAuthenticator::PopPegasusDtimeRow(PegasusDtimeRow& row)
{
    return engine_.PopPegasusDtimeRow(row);
}

int32_t OsnmaAuthenticator::PegasusEphRowCount() const
{
    return engine_.PegasusEphRowCount();
}

int32_t OsnmaAuthenticator::PegasusIonoRowCount() const
{
    return engine_.PegasusIonoRowCount();
}

int32_t OsnmaAuthenticator::PegasusDtimeRowCount() const
{
    return engine_.PegasusDtimeRowCount();
}

bool OsnmaAuthenticator::PopPegasusLogRow(PegasusLogRow& row)
{
    return engine_.PopPegasusLogRow(row);
}

int32_t OsnmaAuthenticator::PegasusLogRowCount() const
{
    return engine_.PegasusLogRowCount();
}

void OsnmaAuthenticator::AddPegasusLogRow(const PegasusLogRow& row)
{
    engine_.AddPegasusLogRow(row);
}

bool OsnmaAuthenticator::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return engine_.SetMerkleRoot(root_32_bytes);
}

bool OsnmaAuthenticator::AddTrustedPublicKey(const OsnmaDsmPkr& public_key)
{
    return engine_.AddTrustedPublicKey(public_key);
}
