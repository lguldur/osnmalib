#include "osnma_raw_json_reader.h"
#include "osnma_bit_utils.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    constexpr int64_t GST_WEEK_SECONDS = 604800;

    // OSNMAlib JSONL files are written in chunks that can be internally
    // reverse-ordered. Keep a bounded time window and release records in GST
    // order before feeding the authenticator.
    constexpr int64_t JSON_REORDER_WINDOW_SECONDS = 600;
    constexpr int32_t JSON_REORDER_MAX_BUFFERED_SUBFRAMES = 64;

    struct JsonLineGst
    {
        int32_t wn = 0;
        double tow = 0.0;
    };

    struct JsonPendingSubframe
    {
        int64_t gst_seconds = 0;
        int32_t input_line = 0;
        std::vector<OsnmaRawJsonReader::Page> pages;
    };

    class JsonCursor
    {
    public:
        explicit JsonCursor(std::string_view text)
            : m_current(text.data()),
              m_end(text.data() + text.size())
        {
        }

        void SkipWhitespace()
        {
            while (m_current < m_end)
            {
                const char c = *m_current;
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                    break;

                ++m_current;
            }
        }

        bool Consume(char expected)
        {
            SkipWhitespace();

            if (m_current >= m_end || *m_current != expected)
                return false;

            ++m_current;
            return true;
        }

        bool ReadString(std::string_view& value)
        {
            SkipWhitespace();

            if (m_current >= m_end || *m_current != '"')
                return false;

            ++m_current;
            const char* start = m_current;
            bool escaped = false;

            while (m_current < m_end)
            {
                const char c = *m_current++;

                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (c == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (c == '"')
                {
                    value = std::string_view(start,
                        static_cast<std::size_t>((m_current - 1) - start));
                    return true;
                }
            }

            return false;
        }

        bool ReadNull()
        {
            SkipWhitespace();

            if ((m_end - m_current) < 4 ||
                m_current[0] != 'n' ||
                m_current[1] != 'u' ||
                m_current[2] != 'l' ||
                m_current[3] != 'l')
            {
                return false;
            }

            m_current += 4;
            return true;
        }

        bool ReadInt32(int32_t& value)
        {
            std::string_view token{};
            if (!ReadNumberToken(token))
                return false;

            if (!token.empty() && token.front() == '+')
                token.remove_prefix(1);

            const char* first = token.data();
            const char* last = first + token.size();
            const auto result = std::from_chars(first, last, value, 10);

            return result.ec == std::errc{} && result.ptr == last;
        }

        bool ReadDouble(double& value)
        {
            std::string_view token{};
            if (!ReadNumberToken(token))
                return false;

            if (!token.empty() && token.front() == '+')
                token.remove_prefix(1);

            const char* first = token.data();
            const char* last = first + token.size();
            const auto result = std::from_chars(first,
                last,
                value,
                std::chars_format::general);

            return result.ec == std::errc{} && result.ptr == last;
        }

        bool SkipValue()
        {
            SkipWhitespace();

            if (m_current >= m_end)
                return false;

            if (*m_current == '"')
            {
                std::string_view ignored{};
                return ReadString(ignored);
            }

            if (*m_current == '{')
            {
                ++m_current;
                SkipWhitespace();

                if (m_current < m_end && *m_current == '}')
                {
                    ++m_current;
                    return true;
                }

                while (m_current < m_end)
                {
                    std::string_view key{};
                    if (!ReadString(key) || !Consume(':') || !SkipValue())
                        return false;

                    SkipWhitespace();

                    if (m_current < m_end && *m_current == '}')
                    {
                        ++m_current;
                        return true;
                    }

                    if (m_current >= m_end || *m_current != ',')
                        return false;

                    ++m_current;
                }

                return false;
            }

            if (*m_current == '[')
            {
                ++m_current;
                SkipWhitespace();

                if (m_current < m_end && *m_current == ']')
                {
                    ++m_current;
                    return true;
                }

                while (m_current < m_end)
                {
                    if (!SkipValue())
                        return false;

                    SkipWhitespace();

                    if (m_current < m_end && *m_current == ']')
                    {
                        ++m_current;
                        return true;
                    }

                    if (m_current >= m_end || *m_current != ',')
                        return false;

                    ++m_current;
                }

                return false;
            }

            if (ReadNull())
                return true;

            if (ConsumeLiteral("true") || ConsumeLiteral("false"))
                return true;

            std::string_view number{};
            return ReadNumberToken(number);
        }

    private:
        bool ConsumeLiteral(std::string_view literal)
        {
            SkipWhitespace();

            if (static_cast<std::size_t>(m_end - m_current) < literal.size())
                return false;

            if (std::string_view(m_current, literal.size()) != literal)
                return false;

            m_current += literal.size();
            return true;
        }

        bool ReadNumberToken(std::string_view& token)
        {
            SkipWhitespace();

            const char* start = m_current;

            if (m_current < m_end && (*m_current == '-' || *m_current == '+'))
                ++m_current;

            const char* integer_start = m_current;
            while (m_current < m_end && *m_current >= '0' && *m_current <= '9')
                ++m_current;

            if (m_current == integer_start)
            {
                m_current = start;
                return false;
            }

            if (m_current < m_end && *m_current == '.')
            {
                ++m_current;
                const char* fractional_start = m_current;

                while (m_current < m_end && *m_current >= '0' && *m_current <= '9')
                    ++m_current;

                if (m_current == fractional_start)
                {
                    m_current = start;
                    return false;
                }
            }

            if (m_current < m_end && (*m_current == 'e' || *m_current == 'E'))
            {
                ++m_current;

                if (m_current < m_end && (*m_current == '-' || *m_current == '+'))
                    ++m_current;

                const char* exponent_start = m_current;
                while (m_current < m_end && *m_current >= '0' && *m_current <= '9')
                    ++m_current;

                if (m_current == exponent_start)
                {
                    m_current = start;
                    return false;
                }
            }

            token = std::string_view(start,
                static_cast<std::size_t>(m_current - start));
            return true;
        }

    private:
        const char* m_current = nullptr;
        const char* m_end = nullptr;
    };

    static int64_t ToGstSeconds(int32_t wn, double tow)
    {
        return static_cast<int64_t>(wn) * GST_WEEK_SECONDS +
            static_cast<int64_t>(std::llround(tow));
    }

    static bool FindJsonValue(std::string_view line,
        std::string_view quoted_key,
        std::string_view& value_tail)
    {
        const std::size_t key_pos = line.find(quoted_key);
        if (key_pos == std::string_view::npos)
            return false;

        std::size_t pos = key_pos + quoted_key.size();

        while (pos < line.size() &&
            (line[pos] == ' ' || line[pos] == '\t' ||
             line[pos] == '\r' || line[pos] == '\n'))
        {
            ++pos;
        }

        if (pos >= line.size() || line[pos] != ':')
            return false;

        ++pos;
        value_tail = line.substr(pos);
        return true;
    }

    static bool ParseGstPair(std::string_view value_tail,
        JsonLineGst& out)
    {
        JsonCursor cursor(value_tail);

        if (!cursor.Consume('[') ||
            !cursor.ReadInt32(out.wn) ||
            !cursor.Consume(',') ||
            !cursor.ReadDouble(out.tow) ||
            !cursor.Consume(']'))
        {
            return false;
        }

        return true;
    }

    static bool ExtractLineGst(std::string_view line, JsonLineGst& out)
    {
        // Schema-style status log:
        //     "GST_subframe": [WN, TOW]
        std::string_view value_tail{};

        if (FindJsonValue(line, "\"GST_subframe\"", value_tail))
            return ParseGstPair(value_tail, out);

        // Current OSNMAlib.eu quick JSONL export:
        //     {"WN":1397,"TOW":150,...}
        if (!FindJsonValue(line, "\"WN\"", value_tail))
            return false;

        {
            JsonCursor cursor(value_tail);
            if (!cursor.ReadInt32(out.wn))
                return false;
        }

        if (!FindJsonValue(line, "\"TOW\"", value_tail))
            return false;

        {
            JsonCursor cursor(value_tail);
            if (!cursor.ReadDouble(out.tow))
                return false;
        }

        return true;
    }

    static bool ParseDecimalInt32(std::string_view text, int32_t& value)
    {
        if (text.empty())
            return false;

        const char* first = text.data();
        const char* last = first + text.size();
        const auto result = std::from_chars(first, last, value, 10);

        return result.ec == std::errc{} && result.ptr == last;
    }
}

bool OsnmaRawJsonReader::ReadFile(const char* filename,
    PageCallback callback,
    Stats* stats,
    int32_t raw_to_word_bit_offset)
{
    if (stats != nullptr)
        *stats = Stats{};

    Stats local_stats{};

    if (filename == nullptr || filename[0] == '\0')
        return false;

    if (!callback)
        return false;

    std::ifstream in(filename);

    if (!in.is_open())
        return false;

    std::map<int64_t, std::vector<JsonPendingSubframe>> reorder_buffer;
    int32_t buffered_subframe_count = 0;
    int64_t newest_seen = std::numeric_limits<int64_t>::min();
    bool have_newest_seen = false;

    auto flush_one_oldest = [&]() -> bool
    {
        if (reorder_buffer.empty())
            return true;

        auto it = reorder_buffer.begin();
        std::vector<JsonPendingSubframe> pending_list = std::move(it->second);
        reorder_buffer.erase(it);

        buffered_subframe_count -= static_cast<int32_t>(pending_list.size());

        std::sort(pending_list.begin(),
            pending_list.end(),
            [](const JsonPendingSubframe& a, const JsonPendingSubframe& b)
            {
                return a.input_line < b.input_line;
            });

        std::vector<Page> pages;
        for (JsonPendingSubframe& pending : pending_list)
        {
            ++local_stats.reorder_flushed_subframes;
            pages.insert(pages.end(),
                std::make_move_iterator(pending.pages.begin()),
                std::make_move_iterator(pending.pages.end()));
        }

        // JSON data is organised by satellite and there can be more than one
        // input line for the same subframe epoch.  Pegasus consumes every
        // output file as a chronological stream, so feed all pages sharing
        // this buffered epoch by reception time (then deterministically by
        // page index and PRN).
        std::stable_sort(pages.begin(),
            pages.end(),
            [](const Page& a, const Page& b)
            {
                if (a.page_time.wn != b.page_time.wn)
                    return a.page_time.wn < b.page_time.wn;
                if (a.page_time.tow != b.page_time.tow)
                    return a.page_time.tow < b.page_time.tow;
                if (a.page_index != b.page_index)
                    return a.page_index < b.page_index;
                return a.prn < b.prn;
            });

        for (const Page& page : pages)
        {
            local_stats.last_fed_page_time = page.page_time;
            local_stats.has_last_fed_page_time = true;

            if (!callback(page))
                return false;
        }

        return true;
    };

    auto flush_ready = [&]() -> bool
    {
        while (!reorder_buffer.empty())
        {
            const int64_t oldest = reorder_buffer.begin()->first;

            const bool watermark_ready =
                have_newest_seen &&
                ((newest_seen - oldest) >= JSON_REORDER_WINDOW_SECONDS);

            const bool buffer_too_deep =
                buffered_subframe_count > JSON_REORDER_MAX_BUFFERED_SUBFRAMES;

            if (!watermark_ready && !buffer_too_deep)
                break;

            if (!flush_one_oldest())
                return false;
        }

        return true;
    };

    std::string line;

    while (std::getline(in, line))
    {
        ++local_stats.line_count;

        if (line.empty())
            continue;

        JsonLineGst gst{};
        if (!ExtractLineGst(line, gst))
        {
            ++local_stats.malformed_line_count;
            continue;
        }

        const int64_t line_gst_seconds = ToGstSeconds(gst.wn, gst.tow);

        if (have_newest_seen && line_gst_seconds < newest_seen)
        {
            ++local_stats.reorder_out_of_order_subframes;

            const int64_t lateness = newest_seen - line_gst_seconds;
            if (lateness > static_cast<int64_t>(local_stats.reorder_max_lateness_s))
                local_stats.reorder_max_lateness_s = static_cast<int32_t>(lateness);
        }

        if (!have_newest_seen || line_gst_seconds > newest_seen)
        {
            newest_seen = line_gst_seconds;
            have_newest_seen = true;
        }

        JsonPendingSubframe pending{};
        pending.gst_seconds = line_gst_seconds;
        pending.input_line = local_stats.line_count;
        pending.pages.reserve(256);

        const bool ok =
            ParseLine(line,
                gst.wn,
                gst.tow,
                [&](const Page& page) -> bool
                {
                    pending.pages.push_back(page);
                    return true;
                },
                local_stats,
                raw_to_word_bit_offset);

        if (!ok)
            return false;

        reorder_buffer[line_gst_seconds].push_back(std::move(pending));
        ++buffered_subframe_count;
        ++local_stats.reorder_buffered_subframes;

        if (buffered_subframe_count > local_stats.reorder_max_buffered_subframes)
            local_stats.reorder_max_buffered_subframes = buffered_subframe_count;

        if (!flush_ready())
            return false;
    }

    // EOF: whatever is left is now safe to flush in chronological order.
    while (!reorder_buffer.empty())
    {
        if (!flush_one_oldest())
            return false;
    }

    if (stats != nullptr)
        *stats = local_stats;

    return true;
}

bool OsnmaRawJsonReader::FeedFileToAuthenticator(const char* filename,
    OsnmaAuthenticator& authenticator,
    Stats* stats,
    NavSignalSource source,
    int32_t native_source_code,
    bool crc_ok,
    int32_t raw_to_word_bit_offset)
{
    Stats read_stats{};
    int32_t fed_count = 0;

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

bool OsnmaRawJsonReader::ParseLine(const std::string& line,
    int32_t wn,
    double tow,
    PageCallback callback,
    Stats& stats,
    int32_t raw_to_word_bit_offset)
{
    ++stats.subframe_count;

    std::string_view value_tail{};
    if (!FindJsonValue(line, "\"svid_bits\"", value_tail))
    {
        ++stats.malformed_line_count;
        return true;
    }

    JsonCursor cursor(value_tail);

    if (!cursor.Consume('{'))
    {
        ++stats.malformed_line_count;
        return true;
    }

    if (cursor.Consume('}'))
        return true;

    while (true)
    {
        std::string_view prn_text{};
        if (!cursor.ReadString(prn_text) || !cursor.Consume(':'))
        {
            ++stats.malformed_line_count;
            return true;
        }

        int32_t prn = -1;
        const bool numeric_prn = ParseDecimalInt32(prn_text, prn);

        if (!numeric_prn)
        {
            if (!cursor.SkipValue())
            {
                ++stats.malformed_line_count;
                return true;
            }
        }
        else
        {
            if (!cursor.Consume('{'))
            {
                if (!cursor.SkipValue())
                {
                    ++stats.malformed_line_count;
                    return true;
                }

                ++stats.missing_e1b_array_count;
            }
            else
            {
                bool found_e1b = false;

                if (!cursor.Consume('}'))
                {
                    while (true)
                    {
                        std::string_view signal_name{};
                        if (!cursor.ReadString(signal_name) || !cursor.Consume(':'))
                        {
                            ++stats.malformed_line_count;
                            return true;
                        }

                        if (signal_name == "E1-B")
                        {
                            found_e1b = true;

                            if (!cursor.Consume('['))
                            {
                                ++stats.malformed_line_count;
                                return true;
                            }

                            int32_t page_index = 0;

                            if (!cursor.Consume(']'))
                            {
                                while (true)
                                {
                                    bool valid_item = false;
                                    std::string_view hex{};

                                    if (cursor.ReadNull())
                                    {
                                        ++stats.null_page_count;
                                        valid_item = true;
                                    }
                                    else if (cursor.ReadString(hex))
                                    {
                                        valid_item = true;

                                        Page page{};
                                        page.prn = prn;
                                        page.page_index = page_index;
                                        page.page_time.wn = wn;
                                        page.page_time.tow =
                                            tow + 2.0 * static_cast<double>(page_index);

                                        if (!HexToBytes(hex,
                                            page.raw_240b.data(),
                                            static_cast<int32_t>(page.raw_240b.size())))
                                        {
                                            ++stats.malformed_hex_count;
                                        }
                                        else if (!CopyInavWordFromRawPage(
                                            page.raw_240b.data(),
                                            page.even_128b.data()))
                                        {
                                            ++stats.malformed_hex_count;
                                        }
                                        else
                                        {
                                            static constexpr int32_t RAW_HALF_BITS = 120;

                                            const int32_t odd_offset =
                                                (raw_to_word_bit_offset == 0)
                                                ? RAW_HALF_BITS
                                                : RAW_HALF_BITS - 1;

                                            const int32_t odd_bit_count =
                                                RAW_PAGE_BITS - odd_offset;

                                            if (odd_bit_count <= 0 ||
                                                odd_bit_count > OSNMA_WORD_BITS ||
                                                !CopyBitsMsb0Shifted(
                                                    page.raw_240b.data(),
                                                    odd_offset,
                                                    RAW_PAGE_BITS,
                                                    page.odd_128b.data(),
                                                    odd_bit_count))
                                            {
                                                ++stats.malformed_hex_count;
                                            }
                                            else
                                            {
                                                const int32_t wt =
                                                    GetUnsignedBitsMsb0(
                                                        page.even_128b.data(),
                                                        0,
                                                        6);

                                                if (wt >= 0 &&
                                                    wt < static_cast<int32_t>(
                                                        stats.wt_count.size()))
                                                {
                                                    ++stats.wt_count[wt];
                                                }

                                                ++stats.page_count;

                                                if (!callback(page))
                                                    return false;
                                            }
                                        }
                                    }

                                    if (!valid_item)
                                    {
                                        if (!cursor.SkipValue())
                                        {
                                            ++stats.malformed_line_count;
                                            return true;
                                        }

                                        ++stats.malformed_hex_count;
                                    }

                                    ++page_index;

                                    if (cursor.Consume(']'))
                                        break;

                                    if (!cursor.Consume(','))
                                    {
                                        ++stats.malformed_line_count;
                                        return true;
                                    }
                                }
                            }
                        }
                        else
                        {
                            if (!cursor.SkipValue())
                            {
                                ++stats.malformed_line_count;
                                return true;
                            }
                        }

                        if (cursor.Consume('}'))
                            break;

                        if (!cursor.Consume(','))
                        {
                            ++stats.malformed_line_count;
                            return true;
                        }
                    }
                }

                if (!found_e1b)
                    ++stats.missing_e1b_array_count;
            }
        }

        if (cursor.Consume('}'))
            break;

        if (!cursor.Consume(','))
        {
            ++stats.malformed_line_count;
            return true;
        }
    }

    return true;
}

bool OsnmaRawJsonReader::HexToBytes(std::string_view hex,
    std::uint8_t* out,
    int32_t out_size_bytes)
{
    if (out == nullptr || out_size_bytes <= 0)
        return false;

    if (static_cast<int32_t>(hex.size()) != out_size_bytes * 2)
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
        const int32_t hi =
            hex_value(hex[static_cast<std::size_t>(2 * i)]);

        const int32_t lo =
            hex_value(hex[static_cast<std::size_t>(2 * i + 1)]);

        if (hi < 0 || lo < 0)
            return false;

        out[i] =
            static_cast<std::uint8_t>((hi << 4) | lo);
    }

    return true;
}

bool OsnmaRawJsonReader::CopyInavWordFromRawPage(const std::uint8_t* raw_240b,
    std::uint8_t* dst_128b)
{
    if (raw_240b == nullptr || dst_128b == nullptr)
        return false;

    std::memset(dst_128b, 0, OSNMA_WORD_BYTES);

    // Galileo I/NAV word contents: 112 bits from the even page part,
    // followed by 16 bits from the odd page part.
    for (int32_t i = 0; i < 112; ++i)
        SetBitMsb0(dst_128b, i, GetBitMsb0(raw_240b, 2 + i));

    for (int32_t i = 0; i < 16; ++i)
        SetBitMsb0(dst_128b, 112 + i, GetBitMsb0(raw_240b, 122 + i));

    return true;
}

bool OsnmaRawJsonReader::CopyBitsMsb0Shifted(const std::uint8_t* src,
    int32_t src_bit_offset,
    int32_t src_bit_capacity,
    std::uint8_t* dst,
    int32_t dst_bit_count)
{
    if (src == nullptr || dst == nullptr)
        return false;

    if (src_bit_offset < 0 || src_bit_capacity <= 0 || dst_bit_count <= 0)
        return false;

    if ((src_bit_offset + dst_bit_count) > src_bit_capacity)
        return false;

    const int32_t dst_size_bytes =
        (dst_bit_count + 7) / 8;

    std::memset(dst,
        0,
        static_cast<std::size_t>(dst_size_bytes));

    for (int32_t i = 0; i < dst_bit_count; ++i)
    {
        const bool bit =
            GetBitMsb0(src,
                src_bit_offset + i);

        SetBitMsb0(dst,
            i,
            bit);
    }

    return true;
}

bool OsnmaRawJsonReader::GetBitMsb0(const std::uint8_t* data,
    int32_t bit_index)
{
    const int32_t byte_index =
        bit_index / 8;

    const int32_t bit_in_byte =
        bit_index % 8;

    const std::uint8_t mask =
        static_cast<std::uint8_t>(0x80u >> bit_in_byte);

    return (data[byte_index] & mask) != 0;
}

void OsnmaRawJsonReader::SetBitMsb0(std::uint8_t* data,
    int32_t bit_index,
    bool value)
{
    const int32_t byte_index =
        bit_index / 8;

    const int32_t bit_in_byte =
        bit_index % 8;

    const std::uint8_t mask =
        static_cast<std::uint8_t>(0x80u >> bit_in_byte);

    if (value)
        data[byte_index] |= mask;
    else
        data[byte_index] &= static_cast<std::uint8_t>(~mask);
}
