#include "pegasus_csv_writer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "pegasus_log_rows.h"
#include "pegasus_nav_rows.h"

namespace
{
    class CsvLine
    {
    public:
        explicit CsvLine(std::FILE* file)
            : file_(file)
        {
        }

        void Empty()
        {
            Separator();
        }

        void Integer(std::int64_t value)
        {
            Separator();
            std::fprintf(file_, "%lld", static_cast<long long>(value));
        }

        template <typename Enum>
        void EnumValue(Enum value)
        {
            Integer(static_cast<std::int64_t>(value));
        }

        void OptionalInteger(const std::optional<int32_t>& value)
        {
            if (value.has_value())
                Integer(*value);
            else
                Empty();
        }

        void Week(int32_t value)
        {
            if (value == PEGASUS_INVALID_WEEK)
                Empty();
            else
                Integer(value);
        }

        void Double(double value)
        {
            Separator();
            if (std::isfinite(value) && value != PEGASUS_INVALID_TOM)
                std::fprintf(file_, "%.17g", value);
        }

        void OptionalDouble(const std::optional<double>& value)
        {
            if (value.has_value())
                Double(*value);
            else
                Empty();
        }

        void Tom(double value)
        {
            Double(value);
        }

        void OptionalEnum(const std::optional<OsnmaAdkd>& value)
        {
            if (value.has_value())
                EnumValue(*value);
            else
                Empty();
        }

        template <typename Enum>
        void OptionalGenericEnum(const std::optional<Enum>& value)
        {
            if (value.has_value())
                EnumValue(*value);
            else
                Empty();
        }

        void Hex(std::uint64_t value, int32_t digits)
        {
            Separator();
            std::fprintf(file_, "\"0x%0*llX\"",
                digits,
                static_cast<unsigned long long>(value));
        }

        void Text(const std::string& value)
        {
            Separator();
            std::fputc('"', file_);
            for (const char c : value)
            {
                if (c == '"')
                    std::fputc('"', file_);
                std::fputc(c, file_);
            }
            std::fputc('"', file_);
        }

        void End()
        {
            std::fputc('\n', file_);
        }

    private:
        void Separator()
        {
            if (!first_)
                std::fputc(';', file_);
            first_ = false;
        }

    private:
        std::FILE* file_ = nullptr;
        bool first_ = true;
    };

    bool WriteHeader(std::FILE* file,
        const char* const* columns,
        std::size_t count)
    {
        if (file == nullptr || columns == nullptr)
            return false;

        for (std::size_t i = 0; i < count; ++i)
        {
            if (i != 0)
                std::fputc(';', file);
            std::fprintf(file, "\"%s\"", columns[i]);
        }
        std::fputc('\n', file);
        return true;
    }

    std::FILE* OpenFile(const std::filesystem::path& filename)
    {
#if defined(_MSC_VER)
        std::FILE* file = nullptr;
        if (fopen_s(&file, filename.string().c_str(), "wb") != 0)
            return nullptr;
        return file;
#else
        return std::fopen(filename.string().c_str(), "wb");
#endif
    }

    void WriteCommon(CsvLine& line,
        int32_t rx_week,
        double rx_tom,
        int32_t prn,
        AuthState auth_status,
        AuthReason auth_reason,
        int32_t auth_week,
        double auth_tom,
        const std::optional<OsnmaAdkd>& auth_adkd,
        std::int64_t auth_bits,
        std::uint64_t fingerprint)
    {
        line.Week(rx_week);
        line.Tom(rx_tom);
        line.Integer(prn);
        line.EnumValue(auth_status);
        line.EnumValue(auth_reason);
        line.Week(auth_week);
        line.Tom(auth_tom);
        line.OptionalEnum(auth_adkd);
        line.Integer(auth_bits);
        line.Hex(fingerprint, 16);
    }

    void WriteEphRow(std::FILE* file, const PegasusEphRow& row)
    {
        CsvLine line(file);
        WriteCommon(line,
            row.rx_week, row.rx_tom, row.prn,
            row.auth_status, row.auth_reason,
            row.auth_week, row.auth_tom,
            row.auth_adkd, row.auth_bits,
            row.nav_fingerprint);

        line.Week(row.toc_week);
        line.Tom(row.toc_tom);
        line.Double(row.af0);
        line.Double(row.af1);
        line.Double(row.af2);
        line.Integer(row.iodnav);
        line.Double(row.c_rs);
        line.Double(row.delta_n);
        line.Double(row.m_0);
        line.Double(row.c_uc);
        line.Double(row.eccentricity);
        line.Double(row.c_us);
        line.Double(row.sqrt_a);
        line.Week(row.toe_week);
        line.Tom(row.toe);
        line.Double(row.c_ic);
        line.Double(row.omega_0);
        line.Double(row.c_is);
        line.Double(row.i_0);
        line.Double(row.c_rc);
        line.Double(row.omega);
        line.Double(row.omega_dot);
        line.Double(row.i_dot);
        line.Hex(row.data_sources, 8);
        line.Integer(row.sisa);
        line.Hex(row.sv_health, 8);
        line.Double(row.bgd_e5a_e1);
        line.Double(row.bgd_e5b_e1);
        line.Week(row.tx_week);
        line.Tom(row.tx_tom);
        line.End();
    }

    void WriteIonoRow(std::FILE* file, const PegasusIonoRow& row)
    {
        CsvLine line(file);
        WriteCommon(line,
            row.rx_week, row.rx_tom, row.prn,
            row.auth_status, row.auth_reason,
            row.auth_week, row.auth_tom,
            row.auth_adkd, row.auth_bits,
            row.nav_fingerprint);
        line.Double(row.ai0);
        line.Double(row.ai1);
        line.Double(row.ai2);
        line.Hex(row.storm_flags, 2);
        line.Week(row.tx_week);
        line.Tom(row.tx_tom);
        line.End();
    }

    void WriteDtimeRow(std::FILE* file, const PegasusDtimeRow& row)
    {
        CsvLine line(file);
        WriteCommon(line,
            row.rx_week, row.rx_tom, row.prn,
            row.auth_status, row.auth_reason,
            row.auth_week, row.auth_tom,
            row.auth_adkd, row.auth_bits,
            row.nav_fingerprint);
        line.EnumValue(row.target_time_system);
        line.Double(row.a0);
        line.Double(row.a1);
        line.OptionalDouble(row.a2);
        line.Week(row.reference_week);
        line.Tom(row.reference_tom);
        line.Week(row.tx_week);
        line.Tom(row.tx_tom);
        line.End();
    }

    void WriteLogRow(std::FILE* file, const PegasusLogRow& row)
    {
        CsvLine line(file);
        if (row.rx_week.has_value()) line.Integer(*row.rx_week); else line.Empty();
        if (row.rx_tom.has_value()) line.Double(*row.rx_tom); else line.Empty();
        line.OptionalInteger(row.prn);
        line.EnumValue(row.severity);
        line.EnumValue(row.event);
        line.OptionalGenericEnum(row.auth_reason);
        line.OptionalInteger(row.stage);
        line.OptionalInteger(row.wt);
        line.OptionalInteger(row.dsm_id);
        line.OptionalInteger(row.block_id);
        line.OptionalInteger(row.tag_index);
        line.OptionalInteger(row.ctr);
        line.OptionalInteger(row.related_prn);
        line.OptionalGenericEnum(row.adkd);
        line.OptionalInteger(row.cop);
        if (row.count.has_value()) line.Integer(*row.count); else line.Empty();
        line.OptionalGenericEnum(row.source);
        line.OptionalInteger(row.raw_source);
        if (!row.detail.empty()) line.Text(row.detail); else line.Empty();
        line.End();
    }

    template <typename Row>
    bool PegasusRxLess(const Row& a, const Row& b)
    {
        const bool a_valid =
            a.rx_week != PEGASUS_INVALID_WEEK &&
            std::isfinite(a.rx_tom) &&
            a.rx_tom != PEGASUS_INVALID_TOM;
        const bool b_valid =
            b.rx_week != PEGASUS_INVALID_WEEK &&
            std::isfinite(b.rx_tom) &&
            b.rx_tom != PEGASUS_INVALID_TOM;

        if (a_valid != b_valid)
            return a_valid;
        if (!a_valid)
            return false;
        if (a.rx_week != b.rx_week)
            return a.rx_week < b.rx_week;
        return a.rx_tom < b.rx_tom;
    }

    bool PegasusLogRxLess(const PegasusLogRow& a, const PegasusLogRow& b)
    {
        const bool a_valid = a.rx_week.has_value() &&
            a.rx_tom.has_value() && std::isfinite(*a.rx_tom);
        const bool b_valid = b.rx_week.has_value() &&
            b.rx_tom.has_value() && std::isfinite(*b.rx_tom);

        if (a_valid != b_valid)
            return a_valid;
        if (!a_valid)
            return false;
        if (*a.rx_week != *b.rx_week)
            return *a.rx_week < *b.rx_week;
        return *a.rx_tom < *b.rx_tom;
    }

    void AddReaderSummaryLogs(const OsnmaRawJsonReader::Stats& stats,
        std::vector<PegasusLogRow>& logs)
    {
        const auto set_summary_time = [&stats](PegasusLogRow& row)
        {
            if (!stats.has_last_fed_page_time ||
                !IsTimeValid(stats.last_fed_page_time))
            {
                return;
            }

            row.rx_week = stats.last_fed_page_time.wn +
                GALILEO_GST_TO_GPS_WEEK_OFFSET;
            row.rx_tom = stats.last_fed_page_time.tow;
        };

        const auto add = [&logs, &set_summary_time](PegasusLogEvent event,
            std::int64_t count,
            const char* detail)
        {
            if (count <= 0)
                return;
            PegasusLogRow row{};
            set_summary_time(row);
            row.severity = PegasusLogSeverity::Warning;
            row.event = event;
            row.count = count;
            row.detail = detail != nullptr ? detail : "";
            logs.push_back(row);
        };

        add(PegasusLogEvent::InputMalformedLine,
            stats.malformed_line_count,
            "Malformed JSONL input lines skipped");
        add(PegasusLogEvent::InputMalformedHex,
            stats.malformed_hex_count,
            "Malformed hexadecimal page strings skipped");
        add(PegasusLogEvent::InputMissingE1bArray,
            stats.missing_e1b_array_count,
            "JSONL records without an E1-B page array");
        add(PegasusLogEvent::InputNullPage,
            stats.null_page_count,
            "Null E1-B page entries");

        if (stats.reorder_out_of_order_subframes > 0)
        {
            PegasusLogRow row{};
            set_summary_time(row);
            row.severity = PegasusLogSeverity::Information;
            row.event = PegasusLogEvent::InputOutOfOrder;
            row.count = stats.reorder_out_of_order_subframes;
            row.detail = "Out-of-order JSONL subframes reordered; maximum lateness seconds=" +
                std::to_string(stats.reorder_max_lateness_s);
            logs.push_back(row);
        }
    }
}

bool PegasusCsvWriter::Write(const char* prefix,
    OsnmaAuthenticator& authenticator,
    const OsnmaRawJsonReader::Stats& reader_stats,
    Result& result)
{
    result = Result{};

    if (prefix == nullptr || prefix[0] == '\0')
        return false;

    const std::string base(prefix);
    const std::filesystem::path eph_path(base + "_cnv.eph");
    const std::filesystem::path iono_path(base + "_cnv.iono");
    const std::filesystem::path dtime_path(base + "_cnv.dtime");
    const std::filesystem::path log_path(base + "_cnv.osnmalog");

    std::FILE* eph = OpenFile(eph_path);
    std::FILE* iono = OpenFile(iono_path);
    std::FILE* dtime = OpenFile(dtime_path);
    std::FILE* log = OpenFile(log_path);

    if (eph == nullptr || iono == nullptr || dtime == nullptr || log == nullptr)
    {
        if (eph != nullptr) std::fclose(eph);
        if (iono != nullptr) std::fclose(iono);
        if (dtime != nullptr) std::fclose(dtime);
        if (log != nullptr) std::fclose(log);
        return false;
    }

    static constexpr const char* EPH_COLUMNS[] = {
        "RX_WEEK", "RX_TOM", "PRN",
        "AUTH_STATUS", "AUTH_REASON", "AUTH_WEEK", "AUTH_TOM",
        "AUTH_ADKD", "AUTH_BITS", "NAV_FINGERPRINT",
        "TOC_WEEK", "TOC_TOM", "AF0", "AF1", "AF2",
        "IODNAV", "C_RS", "DELTA_N", "M_0",
        "C_UC", "ECCENTRICITY", "C_US", "SQRT_A",
        "TOE_WEEK", "TOE", "C_IC", "OMEGA_0", "C_IS", "I_0",
        "C_RC", "OMEGA", "OMEGA_DOT", "I_DOT",
        "DATA_SOURCES", "SISA", "SV_HEALTH",
        "BGD_E5A_E1", "BGD_E5B_E1", "TX_WEEK", "TX_TOM"
    };

    static constexpr const char* IONO_COLUMNS[] = {
        "RX_WEEK", "RX_TOM", "PRN",
        "AUTH_STATUS", "AUTH_REASON", "AUTH_WEEK", "AUTH_TOM",
        "AUTH_ADKD", "AUTH_BITS", "NAV_FINGERPRINT",
        "AI0", "AI1", "AI2", "STORM_FLAGS", "TX_WEEK", "TX_TOM"
    };

    static constexpr const char* DTIME_COLUMNS[] = {
        "RX_WEEK", "RX_TOM", "PRN",
        "AUTH_STATUS", "AUTH_REASON", "AUTH_WEEK", "AUTH_TOM",
        "AUTH_ADKD", "AUTH_BITS", "NAV_FINGERPRINT",
        "TARGET_TIME_SYSTEM", "A0", "A1", "A2",
        "REFERENCE_WEEK", "REFERENCE_TOM", "TX_WEEK", "TX_TOM"
    };

    static constexpr const char* LOG_COLUMNS[] = {
        "RX_WEEK", "RX_TOM", "PRN", "SEVERITY", "EVENT",
        "AUTH_REASON", "STAGE", "WT", "DSM_ID", "BLOCK_ID",
        "TAG_INDEX", "CTR", "RELATED_PRN", "ADKD", "COP", "COUNT",
        "SOURCE", "RAW_SOURCE", "DETAIL"
    };

    WriteHeader(eph, EPH_COLUMNS, std::size(EPH_COLUMNS));
    WriteHeader(iono, IONO_COLUMNS, std::size(IONO_COLUMNS));
    WriteHeader(dtime, DTIME_COLUMNS, std::size(DTIME_COLUMNS));
    WriteHeader(log, LOG_COLUMNS, std::size(LOG_COLUMNS));

    std::vector<PegasusEphRow> eph_rows;
    PegasusEphRow eph_row{};
    while (authenticator.PopPegasusEphRow(eph_row))
        eph_rows.push_back(eph_row);
    std::stable_sort(eph_rows.begin(), eph_rows.end(), PegasusRxLess<PegasusEphRow>);
    for (const PegasusEphRow& row : eph_rows)
    {
        WriteEphRow(eph, row);
        ++result.eph_rows;
    }

    std::vector<PegasusIonoRow> iono_rows;
    PegasusIonoRow iono_row{};
    while (authenticator.PopPegasusIonoRow(iono_row))
        iono_rows.push_back(iono_row);
    std::stable_sort(iono_rows.begin(), iono_rows.end(), PegasusRxLess<PegasusIonoRow>);
    for (const PegasusIonoRow& row : iono_rows)
    {
        WriteIonoRow(iono, row);
        ++result.iono_rows;
    }

    std::vector<PegasusDtimeRow> dtime_rows;
    PegasusDtimeRow dtime_row{};
    while (authenticator.PopPegasusDtimeRow(dtime_row))
        dtime_rows.push_back(dtime_row);
    std::stable_sort(dtime_rows.begin(), dtime_rows.end(), PegasusRxLess<PegasusDtimeRow>);
    for (const PegasusDtimeRow& row : dtime_rows)
    {
        WriteDtimeRow(dtime, row);
        ++result.dtime_rows;
    }

    std::vector<PegasusLogRow> logs;
    PegasusLogRow log_row{};
    while (authenticator.PopPegasusLogRow(log_row))
        logs.push_back(log_row);

    AddReaderSummaryLogs(reader_stats, logs);
    std::stable_sort(logs.begin(), logs.end(), PegasusLogRxLess);

    for (const PegasusLogRow& row : logs)
    {
        WriteLogRow(log, row);
        ++result.log_rows;
    }

    const bool ok =
        std::fclose(eph) == 0 &&
        std::fclose(iono) == 0 &&
        std::fclose(dtime) == 0 &&
        std::fclose(log) == 0;

    if (!ok)
        return false;

    result.eph_filename = eph_path.string();
    result.iono_filename = iono_path.string();
    result.dtime_filename = dtime_path.string();
    result.log_filename = log_path.string();
    return true;
}
