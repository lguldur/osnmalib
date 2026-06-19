#include "osnma_raw_json_reader.h"
#include "osnma_bit_utils.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <regex>
#include <string>
#include <vector>

namespace
{
    constexpr int64_t GST_WEEK_SECONDS = 604800;

    // The observed OSNMAlib JSONL files are written in chunks that are
    // internally reverse-ordered. A 5-minute watermark is enough for the
    // current files, and still tiny in memory.
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

    static int64_t ToGstSeconds(int32_t wn, double tow)
    {
        return static_cast<int64_t>(wn) * GST_WEEK_SECONDS +
            static_cast<int64_t>(std::llround(tow));
    }

    static bool ExtractLineGst(const std::string& line, JsonLineGst& out)
    {
        // Current OSNMAlib.eu quick JSONL export:
        //     {"WN":1397,"TOW":150,...}
        static const std::regex wn_re(
            R"json("WN"\s*:\s*([0-9]+))json",
            std::regex::ECMAScript);

        static const std::regex tow_re(
            R"json("TOW"\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?))json",
            std::regex::ECMAScript);

        // Schema-style status log:
        //     "GST_subframe": [WN, TOW]
        static const std::regex gst_subframe_re(
            R"json("GST_subframe"\s*:\s*\[\s*([0-9]+)\s*,\s*([-+]?[0-9]+(?:\.[0-9]+)?)\s*\])json",
            std::regex::ECMAScript);

        std::smatch m{};

        if (std::regex_search(line, m, gst_subframe_re) && m.size() >= 3)
        {
            out.wn = static_cast<int32_t>(std::stoi(m[1].str()));
            out.tow = std::stod(m[2].str());
            return true;
        }

        if (!std::regex_search(line, m, wn_re) || m.size() < 2)
            return false;

        out.wn = static_cast<int32_t>(std::stoi(m[1].str()));

        if (!std::regex_search(line, m, tow_re) || m.size() < 2)
            return false;

        out.tow = std::stod(m[1].str());
        return true;
    }

    static int32_t CountBufferedSubframes(
        const std::map<int64_t, std::vector<JsonPendingSubframe>>& buffer)
    {
        int32_t count = 0;

        for (const auto& kv : buffer)
            count += static_cast<int32_t>(kv.second.size());

        return count;
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
    int64_t newest_seen = std::numeric_limits<int64_t>::min();
    bool have_newest_seen = false;

    auto flush_one_oldest = [&]() -> bool
    {
        if (reorder_buffer.empty())
            return true;

        auto it = reorder_buffer.begin();
        std::vector<JsonPendingSubframe> pending_list = std::move(it->second);
        reorder_buffer.erase(it);

        std::sort(pending_list.begin(),
            pending_list.end(),
            [](const JsonPendingSubframe& a, const JsonPendingSubframe& b)
            {
                return a.input_line < b.input_line;
            });

        for (const JsonPendingSubframe& pending : pending_list)
        {
            ++local_stats.reorder_flushed_subframes;

            for (const Page& page : pending.pages)
            {
                if (!callback(page))
                    return false;
            }
        }

        return true;
    };

    auto update_max_depth = [&]()
    {
        const int32_t depth = CountBufferedSubframes(reorder_buffer);
        if (depth > local_stats.reorder_max_buffered_subframes)
            local_stats.reorder_max_buffered_subframes = depth;
    };

    auto flush_ready = [&]() -> bool
    {
        while (!reorder_buffer.empty())
        {
            const int64_t oldest = reorder_buffer.begin()->first;
            const int32_t depth = CountBufferedSubframes(reorder_buffer);

            const bool watermark_ready =
                have_newest_seen &&
                ((newest_seen - oldest) >= JSON_REORDER_WINDOW_SECONDS);

            const bool buffer_too_deep =
                depth > JSON_REORDER_MAX_BUFFERED_SUBFRAMES;

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

        const bool ok =
            ParseLine(line,
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
        ++local_stats.reorder_buffered_subframes;
        update_max_depth();

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
    PageCallback callback,
    Stats& stats,
    int32_t raw_to_word_bit_offset)
{
    /*
        Quick-and-dirty parser for OSNMAlib.eu JSONL lines like:

        {
            "WN":1397,
            "TOW":150,
            "svid_bits":{
                "2":{
                    "E1-B":["...", "..."],
                    "E5b-I":["...", "..."]
                }
            }
        }

        This intentionally does not try to be a general JSON parser.
    */

    JsonLineGst gst{};
    if (!ExtractLineGst(line, gst))
    {
        ++stats.malformed_line_count;
        return true;
    }

    const int32_t wn = gst.wn;
    const double tow = gst.tow;

    ++stats.subframe_count;

    /*
        Match each satellite block:
            "2": { ... }

        This works for the current flat OSNMAlib.eu structure because the
        satellite object contains arrays but no nested objects.
    */
    static const std::regex svid_block_re(
        R"json("([0-9]+)"\s*:\s*\{([^{}]*)\})json",
        std::regex::ECMAScript);


    static const std::regex e1b_array_re(
        R"json("E1-B"\s*:\s*\[([^\]]*)\])json",
        std::regex::ECMAScript);

            const std::sregex_iterator end{};

            for (std::sregex_iterator it(line.begin(), line.end(), svid_block_re);
                it != end;
                ++it)
            {
                const std::smatch& sm = *it;

                if (sm.size() < 3)
                    continue;

                const int32_t prn =
                    static_cast<int32_t>(std::stoi(sm[1].str()));

                const std::string block =
                    sm[2].str();

                std::smatch e1b_match{};

                if (!std::regex_search(block, e1b_match, e1b_array_re) ||
                    e1b_match.size() < 2)
                {
                    ++stats.missing_e1b_array_count;
                    continue;
                }

                const std::string e1b_array =
                    e1b_match[1].str();

                static const std::regex e1b_item_re(
                    R"json("([0-9A-Fa-f]{60})"|\bnull\b)json",
                    std::regex::ECMAScript);

                int32_t page_index = 0;

                for (std::sregex_iterator item(e1b_array.begin(), e1b_array.end(), e1b_item_re);
                    item != end;
                    ++item)
                {
                    const std::smatch& im = *item;

                    if (im.size() >= 2 && im[1].matched)
                    {
                        const std::string hex =
                            im[1].str();

                        Page page{};
                        page.prn = prn;
                        page.page_index = page_index;

                        page.page_time.wn = wn;
                        page.page_time.tow = tow + 2.0 * static_cast<double>(page_index);

                        if (!HexToBytes(hex,
                            page.raw_240b.data(),
                            static_cast<int32_t>(page.raw_240b.size())))
                        {
                            ++stats.malformed_hex_count;
                            ++page_index;
                            continue;
                        }

                        static constexpr int32_t RAW_HALF_BITS = 120;

                        /*
                            Reconstruct the 128-bit Galileo I/NAV word from
                            the two 120-bit page parts. The navigation word is
                            not a contiguous slice of the 240-bit raw page:

                                raw[2 .. 114] || raw[122 .. 138]

                            The previous JSON reader copied a contiguous slice
                            starting at raw bit 1. That still exposed the OSNMA
                            reserved field correctly, so DSM/KROOT/TESLA could
                            verify, but it shifted/corrupted the navigation data
                            used in ADKD0/4/12 tag MAC inputs.
                        */
                        if (!CopyInavWordFromRawPage(page.raw_240b.data(),
                            page.even_128b.data()))
                        {
                            ++stats.malformed_hex_count;
                            ++page_index;
                            continue;
                        }

                        const int32_t odd_offset =
                            (raw_to_word_bit_offset == 0)
                            ? RAW_HALF_BITS
                            : RAW_HALF_BITS - 1;

                        const int32_t odd_bit_count =
                            RAW_PAGE_BITS - odd_offset;

                        if (odd_bit_count <= 0 || odd_bit_count > OSNMA_WORD_BITS)
                        {
                            ++stats.malformed_hex_count;
                            ++page_index;
                            continue;
                        }

                        if (!CopyBitsMsb0Shifted(page.raw_240b.data(),
                            odd_offset,
                            RAW_PAGE_BITS,
                            page.odd_128b.data(),
                            odd_bit_count))
                        {
                            ++stats.malformed_hex_count;
                            ++page_index;
                            continue;
                        }

                        const int32_t wt =
                            GetUnsignedBitsMsb0(page.even_128b.data(), 0, 6);

                        if (wt >= 0 && wt < static_cast<int32_t>(stats.wt_count.size()))
                            ++stats.wt_count[wt];

                        ++stats.page_count;

                        if (!callback(page))
                            return false;
                    }
                    else
                    {
                        ++stats.null_page_count;
                    }

                    ++page_index;
                }
            }

            return true;
}

bool OsnmaRawJsonReader::HexToBytes(const std::string& hex,
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
            hex_value(hex[static_cast<size_t>(2 * i)]);

        const int32_t lo =
            hex_value(hex[static_cast<size_t>(2 * i + 1)]);

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
        static_cast<size_t>(dst_size_bytes));

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
