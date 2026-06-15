#include "osnma_raw_json_reader.h"
#include "osnma_bit_utils.h"

#include <cctype>
#include <cstring>
#include <fstream>
#include <regex>
#include <string>

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

    std::string line;

    while (std::getline(in, line))
    {
        ++local_stats.line_count;

        if (line.empty())
            continue;

        const bool ok =
            ParseLine(line,
                callback,
                local_stats,
                raw_to_word_bit_offset);

        if (!ok)
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

    std::array<std::uint8_t, OSNMA_WORD_BYTES> dummy_odd{};

    const bool ok =
        ReadFile(filename,
            [&](const Page& page) -> bool
            {
                authenticator.FeedRawInavPage(page.prn,
                    page.word_128b.data(),
                    dummy_odd.data(),
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

    static const std::regex wn_re(
        R"json("WN"\s*:\s*([0-9]+))json",
        std::regex::ECMAScript);

    static const std::regex tow_re(
        R"json("TOW"\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?))json",
        std::regex::ECMAScript);

    std::smatch m{};

    if (!std::regex_search(line, m, wn_re) || m.size() < 2)
    {
        ++stats.malformed_line_count;
        return true;
    }

    const int32_t wn =
        static_cast<int32_t>(std::stoi(m[1].str()));

    if (!std::regex_search(line, m, tow_re) || m.size() < 2)
    {
        ++stats.malformed_line_count;
        return true;
    }

    const double tow =
        std::stod(m[1].str());

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

    static const std::regex hex_page_re(
        R"json("([0-9A-Fa-f]{60})")json",
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

                        if (!CopyBitsMsb0Shifted(page.raw_240b.data(),
                            raw_to_word_bit_offset,
                            RAW_PAGE_BITS,
                            page.word_128b.data(),
                            OSNMA_WORD_BITS))
                        {
                            ++stats.malformed_hex_count;
                            ++page_index;
                            continue;
                        }

                        const int32_t wt =
                            GetUnsignedBitsMsb0(page.word_128b.data(), 0, 6);

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
