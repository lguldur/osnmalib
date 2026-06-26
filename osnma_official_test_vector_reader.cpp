// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include "osnma_official_test_vector_reader.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    static constexpr int32_t HEX_CHARS_PER_RAW_PAGE =
        OsnmaOfficialTestVectorReader::RAW_PAGE_BYTES * 2;

    static constexpr int32_t RAW_HALF_BITS = 120;

    static std::string BasenameOnly(const char* filename)
    {
        if (filename == nullptr)
            return {};

        std::string s(filename);

        const std::size_t p = s.find_last_of("/\\");

        if (p != std::string::npos)
            s.erase(0, p + 1);

        return s;
    }

    static std::string Trim(const std::string& in)
    {
        std::size_t first = 0;
        std::size_t last = in.size();

        while (first < last && std::isspace(static_cast<unsigned char>(in[first])) != 0)
            ++first;

        while (last > first && std::isspace(static_cast<unsigned char>(in[last - 1])) != 0)
            --last;

        return in.substr(first, last - first);
    }
}

bool OsnmaOfficialTestVectorReader::ReadFile(const char* filename,
    PageCallback callback,
    Stats* stats,
    int32_t raw_to_word_bit_offset)
{
    if (stats != nullptr)
        *stats = Stats{};

    if (filename == nullptr || filename[0] == '\0')
        return false;

    if (!callback)
        return false;

    Stats local_stats{};

    if (!TryParseStartTimeFromFilename(filename,
        local_stats.start_time))
    {
        return false;
    }

    local_stats.has_start_time = true;

    std::ifstream in(filename);

    if (!in.is_open())
        return false;

    std::string line;

    if (!std::getline(in, line))
        return false;

    std::vector<SatelliteStream> streams;

    while (std::getline(in, line))
    {
        ++local_stats.csv_row_count;

        if (Trim(line).empty())
            continue;

        SatelliteStream stream{};

        if (!ParseCsvRow(line, stream))
        {
            ++local_stats.malformed_row_count;
            continue;
        }

        const int32_t hex_bit_count =
            static_cast<int32_t>(stream.nav_bits_hex.size()) * 4;

        if (stream.num_nav_bits != hex_bit_count ||
            (stream.nav_bits_hex.size() % HEX_CHARS_PER_RAW_PAGE) != 0)
        {
            ++local_stats.inconsistent_length_count;
            continue;
        }

        streams.push_back(std::move(stream));
    }

    local_stats.satellite_count =
        static_cast<int32_t>(streams.size());

    if (streams.empty())
    {
        if (stats != nullptr)
            *stats = local_stats;

        return true;
    }

    int32_t page_count_per_satellite = -1;

    for (const SatelliteStream& stream : streams)
    {
        const int32_t page_count =
            static_cast<int32_t>(stream.nav_bits_hex.size() / HEX_CHARS_PER_RAW_PAGE);

        if (page_count_per_satellite < 0)
        {
            page_count_per_satellite = page_count;
        }
        else if (page_count != page_count_per_satellite)
        {
            ++local_stats.inconsistent_length_count;
            page_count_per_satellite = std::min(page_count_per_satellite, page_count);
        }
    }

    if (page_count_per_satellite < 0)
        page_count_per_satellite = 0;

    local_stats.page_count_per_satellite = page_count_per_satellite;

    for (int32_t global_page_index = 0;
        global_page_index < page_count_per_satellite;
        ++global_page_index)
    {
        for (const SatelliteStream& stream : streams)
        {
            Page page{};

            if (!DecodePage(stream,
                global_page_index,
                local_stats.start_time,
                raw_to_word_bit_offset,
                page))
            {
                ++local_stats.malformed_hex_count;
                continue;
            }

            const int32_t wt =
                GetUnsignedBitsMsb0(page.even_128b.data(), 0, 6);

            if (wt >= 0 && wt < static_cast<int32_t>(local_stats.wt_count.size()))
                ++local_stats.wt_count[wt];

            ++local_stats.page_count;

            if (!callback(page))
            {
                if (stats != nullptr)
                    *stats = local_stats;

                return false;
            }
        }
    }

    if (stats != nullptr)
        *stats = local_stats;

    return true;
}

bool OsnmaOfficialTestVectorReader::FeedFileToAuthenticator(const char* filename,
    OsnmaAuthenticator& authenticator,
    Stats* stats,
    NavSignalSource source,
    int32_t native_source_code,
    bool crc_ok,
    int32_t raw_to_word_bit_offset)
{
    Stats read_stats{};
    int32_t fed_count = 0;

    authenticator.SetNavTimingMode(NavTimingMode::OfficialCsvE1B);

    const bool ok =
        ReadFile(filename,
            [&](const Page& page) -> bool
            {
                authenticator.FeedRawInavPage(page.prn,
                    page.even_128b.data(),
                    page.odd_128b.data(),
                    page.page_time,
                    source,
                    native_source_code,
                    crc_ok);

                ++fed_count;
                return true;
            },
            &read_stats,
            raw_to_word_bit_offset);

    read_stats.fed_page_count = fed_count;

    if (stats != nullptr)
        *stats = read_stats;

    return ok;
}

bool OsnmaOfficialTestVectorReader::TryParseStartTimeFromFilename(const char* filename,
    GnssTime& start_time_out)
{
    start_time_out = GnssTime{};

    const std::string base = BasenameOnly(filename);

    if (base.size() <= 4 || base.compare(base.size() - 4, 4, ".csv") != 0)
        return false;

    const std::string_view stem(base.data(), base.size() - 4);
    std::array<std::string_view, 7> parts{};
    std::size_t first = 0;

    for (std::size_t i = 0; i < parts.size() - 1; ++i)
    {
        const std::size_t separator = stem.find('_', first);
        if (separator == std::string_view::npos)
            return false;

        parts[i] = stem.substr(first, separator - first);
        first = separator + 1;
    }

    parts.back() = stem.substr(first);

    if (parts.back().find('_') != std::string_view::npos ||
        parts[3] != "GST")
    {
        return false;
    }

    auto parse_int =
        [](std::string_view text, int32_t& value) -> bool
        {
            if (text.empty())
                return false;

            const char* begin = text.data();
            const char* end = begin + text.size();
            const auto result = std::from_chars(begin, end, value, 10);

            return result.ec == std::errc{} && result.ptr == end;
        };

    int32_t day = 0;
    int32_t year = 0;
    int32_t hour = 0;
    int32_t minute = 0;
    int32_t second = 0;

    if (!parse_int(parts[0], day) ||
        !parse_int(parts[2], year) ||
        !parse_int(parts[4], hour) ||
        !parse_int(parts[5], minute) ||
        !parse_int(parts[6], second))
    {
        return false;
    }

    int32_t month = 0;

    if (!MonthFromString(std::string(parts[1]), month))
        return false;

    if (day < 1 || day > 31 ||
        hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 ||
        second < 0 || second > 60)
    {
        return false;
    }

    /*
        Galileo System Time epoch:
            1999-08-22 00:00:00 GST
    */
    const std::int64_t epoch_days = DaysFromCivil(1999, 8, 22);
    const std::int64_t current_days = DaysFromCivil(year, month, day);
    const std::int64_t delta_days = current_days - epoch_days;

    if (delta_days < 0)
        return false;

    const std::int64_t seconds_of_week =
        (delta_days % 7) * 86400LL +
        static_cast<std::int64_t>(hour) * 3600LL +
        static_cast<std::int64_t>(minute) * 60LL +
        static_cast<std::int64_t>(second);

    start_time_out.wn =
        static_cast<int32_t>(delta_days / 7);

    start_time_out.tow =
        static_cast<double>(seconds_of_week);

    return IsTimeValid(start_time_out);
}

bool OsnmaOfficialTestVectorReader::ParseCsvRow(const std::string& line,
    SatelliteStream& stream_out)
{
    stream_out = SatelliteStream{};

    const std::size_t c1 = line.find(',');

    if (c1 == std::string::npos)
        return false;

    const std::size_t c2 = line.find(',', c1 + 1);

    if (c2 == std::string::npos)
        return false;

    const std::string svid_str = Trim(line.substr(0, c1));
    const std::string bits_str = Trim(line.substr(c1 + 1, c2 - c1 - 1));
    std::string hex = Trim(line.substr(c2 + 1));

    if (svid_str.empty() || bits_str.empty() || hex.empty())
        return false;

    stream_out.prn = std::stoi(svid_str);
    stream_out.num_nav_bits = std::stoi(bits_str);

    for (char& c : hex)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    stream_out.nav_bits_hex = std::move(hex);

    return stream_out.prn > 0 && stream_out.num_nav_bits > 0;
}

bool OsnmaOfficialTestVectorReader::DecodePage(const SatelliteStream& stream,
    int32_t global_page_index,
    const GnssTime& start_time,
    int32_t raw_to_word_bit_offset,
    Page& page_out)
{
    page_out = Page{};

    if (global_page_index < 0)
        return false;

    const std::size_t hex_offset =
        static_cast<std::size_t>(global_page_index) * HEX_CHARS_PER_RAW_PAGE;

    if (hex_offset + HEX_CHARS_PER_RAW_PAGE > stream.nav_bits_hex.size())
        return false;

    page_out.prn = stream.prn;
    page_out.page_index = global_page_index % 15;
    page_out.global_page_index = global_page_index;

    if (!AdvanceTime(start_time,
        2.0 * static_cast<double>(global_page_index),
        page_out.page_time))
    {
        return false;
    }

    if (!HexToBytes(stream.nav_bits_hex.data() + hex_offset,
        HEX_CHARS_PER_RAW_PAGE,
        page_out.raw_240b.data(),
        static_cast<int32_t>(page_out.raw_240b.size())))
    {
        return false;
    }

    /*
        Daniel Estevez's official test-vector bridge does not take a
        contiguous 128-bit slice from the 240-bit CSV page. It builds the
        Galileo INAV word exactly like this:

            contents = page[2 .. 2 + 112] || page[122 .. 122 + 16]

        The OSNMA field is still taken from the odd page part below. The old
        contiguous extraction happened to work for HKROOT/MACK because those
        bits are in the OSNMA reserved field, but it corrupted the INAV CED
        words used for ADKD0/4/12 tag verification.
    */
    if (!CopyOfficialCsvInavWord(page_out.raw_240b.data(),
        page_out.even_128b.data()))
    {
        return false;
    }

    const int32_t odd_offset =
        (raw_to_word_bit_offset == 0)
        ? RAW_HALF_BITS
        : RAW_HALF_BITS - 1;
    
    const int32_t odd_bit_count = RAW_PAGE_BITS - odd_offset;

    if (odd_bit_count <= 0 || odd_bit_count > OSNMA_WORD_BITS)
        return false;

    if (!CopyBitsMsb0Shifted(page_out.raw_240b.data(),
        odd_offset,
        RAW_PAGE_BITS,
        page_out.odd_128b.data(),
        odd_bit_count))
    {
        return false;
    }

    return true;
}

bool OsnmaOfficialTestVectorReader::HexToBytes(const char* hex,
    int32_t hex_char_count,
    std::uint8_t* out,
    int32_t out_size_bytes)
{
    if (hex == nullptr || out == nullptr || hex_char_count != out_size_bytes * 2)
        return false;

    auto hex_value =
        [](char c) -> int32_t
        {
            if (c >= '0' && c <= '9')
                return c - '0';

            if (c >= 'a' && c <= 'f')
                return 10 + c - 'a';

            if (c >= 'A' && c <= 'F')
                return 10 + c - 'A';

            return -1;
        };

    for (int32_t i = 0; i < out_size_bytes; ++i)
    {
        const int32_t hi = hex_value(hex[2 * i]);
        const int32_t lo = hex_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return false;

        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }

    return true;
}

bool OsnmaOfficialTestVectorReader::CopyBitsMsb0Shifted(const std::uint8_t* src,
    int32_t src_bit_offset,
    int32_t src_bit_capacity,
    std::uint8_t* dst,
    int32_t dst_bit_count)
{
    if (src == nullptr || dst == nullptr)
        return false;

    if (src_bit_offset < 0 || dst_bit_count < 0)
        return false;

    if (src_bit_offset + dst_bit_count > src_bit_capacity)
        return false;

    const int32_t dst_bytes = (dst_bit_count + 7) / 8;

    for (int32_t i = 0; i < dst_bytes; ++i)
        dst[i] = 0;

    for (int32_t i = 0; i < dst_bit_count; ++i)
        SetBitMsb0(dst, i, GetBitMsb0(src, src_bit_offset + i));

    return true;
}

bool OsnmaOfficialTestVectorReader::CopyOfficialCsvInavWord(const std::uint8_t* raw_240b,
    std::uint8_t* dst_128b)
{
    if (raw_240b == nullptr || dst_128b == nullptr)
        return false;

    for (int32_t i = 0; i < OSNMA_WORD_BYTES; ++i)
        dst_128b[i] = 0;

    // Daniel's osnma-test-vectors-to-galmon conversion:
    //   page[2..114] followed by page[122..138].
    for (int32_t i = 0; i < 112; ++i)
        SetBitMsb0(dst_128b, i, GetBitMsb0(raw_240b, 2 + i));

    for (int32_t i = 0; i < 16; ++i)
        SetBitMsb0(dst_128b, 112 + i, GetBitMsb0(raw_240b, 122 + i));

    return true;
}

bool OsnmaOfficialTestVectorReader::GetBitMsb0(const std::uint8_t* data,
    int32_t bit_index)
{
    const int32_t byte_index = bit_index / 8;
    const int32_t bit_in_byte = bit_index % 8;
    const std::uint8_t mask = static_cast<std::uint8_t>(0x80u >> bit_in_byte);

    return (data[byte_index] & mask) != 0;
}

void OsnmaOfficialTestVectorReader::SetBitMsb0(std::uint8_t* data,
    int32_t bit_index,
    bool value)
{
    const int32_t byte_index = bit_index / 8;
    const int32_t bit_in_byte = bit_index % 8;
    const std::uint8_t mask = static_cast<std::uint8_t>(0x80u >> bit_in_byte);

    if (value)
        data[byte_index] |= mask;
    else
        data[byte_index] &= static_cast<std::uint8_t>(~mask);
}

int32_t OsnmaOfficialTestVectorReader::GetUnsignedBitsMsb0(const std::uint8_t* data,
    int32_t first_bit,
    int32_t bit_count)
{
    if (data == nullptr || first_bit < 0 || bit_count < 0 || bit_count > 31)
        return -1;

    int32_t value = 0;

    for (int32_t i = 0; i < bit_count; ++i)
    {
        value <<= 1;

        if (GetBitMsb0(data, first_bit + i))
            value |= 1;
    }

    return value;
}

bool OsnmaOfficialTestVectorReader::AdvanceTime(const GnssTime& start_time,
    double seconds,
    GnssTime& out)
{
    if (!IsTimeValid(start_time))
        return false;

    out = start_time;
    out.tow += seconds;

    while (out.tow >= 604800.0)
    {
        out.tow -= 604800.0;
        ++out.wn;
    }

    while (out.tow < 0.0)
    {
        out.tow += 604800.0;
        --out.wn;
    }

    return IsTimeValid(out);
}

bool OsnmaOfficialTestVectorReader::MonthFromString(const std::string& month,
    int32_t& month_out)
{
    std::string m = month;

    for (char& c : m)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    static const char* months[] =
    {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
    };

    for (int32_t i = 0; i < 12; ++i)
    {
        if (m == months[i])
        {
            month_out = i + 1;
            return true;
        }
    }

    month_out = 0;
    return false;
}

std::int64_t OsnmaOfficialTestVectorReader::DaysFromCivil(int32_t year,
    int32_t month,
    int32_t day)
{
    /*
        Howard Hinnant's civil-date algorithm.
        Returns days relative to 1970-01-01.
    */
    year -= month <= 2 ? 1 : 0;

    const int32_t era =
        (year >= 0 ? year : year - 399) / 400;

    const uint32_t yoe =
        static_cast<uint32_t>(year - era * 400);

    const uint32_t doy =
        (153u * static_cast<uint32_t>(month + (month > 2 ? -3 : 9)) + 2u) / 5u +
        static_cast<uint32_t>(day) - 1u;

    const uint32_t doe =
        yoe * 365u + yoe / 4u - yoe / 100u + doy;

    return static_cast<std::int64_t>(era) * 146097LL +
        static_cast<std::int64_t>(doe) - 719468LL;
}
