#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "gnss_time.h"
#include "nav_signal_source.h"
#include "osnma_authenticator.h"

class OsnmaRawJsonReader
{
public:
    static constexpr int32_t RAW_PAGE_BITS = 240;
    static constexpr int32_t RAW_PAGE_BYTES = 30;

    static constexpr int32_t OSNMA_WORD_BITS = 128;
    static constexpr int32_t OSNMA_WORD_BYTES = 16;

    /*
        OSNMAlib.eu / subframe_bits JSON page.

        One 60-hex-character string:
            30 bytes = 240 bits

        For E1-B, current interpretation:
            OSNMA logical word bit 0 = raw page bit 1
    */
    struct Page
    {
        int32_t prn = -1;
        int32_t page_index = -1;

        GnssTime page_time{};

        std::array<std::uint8_t, RAW_PAGE_BYTES> raw_240b{};
        std::array<std::uint8_t, OSNMA_WORD_BYTES> even_128b{};
        std::array<std::uint8_t, OSNMA_WORD_BYTES> odd_128b{};

        // Compatibility/debug alias candidate can be removed later.
        //std::array<std::uint8_t, OSNMA_WORD_BYTES> word_128b{};
    };

    struct Stats
    {
        int32_t line_count = 0;
        int32_t subframe_count = 0;
        int32_t page_count = 0;

        int32_t malformed_line_count = 0;
        int32_t malformed_hex_count = 0;

        int32_t fed_page_count = 0;

        int32_t missing_e1b_array_count = 0;
        int32_t null_page_count = 0;

        std::array<int32_t, 64> wt_count{};

        // JSONL files may contain 30-second subframe records out of order.
        // The reader reorders them before feeding pages to the caller.
        int32_t reorder_buffered_subframes = 0;
        int32_t reorder_flushed_subframes = 0;
        int32_t reorder_max_buffered_subframes = 0;
        int32_t reorder_out_of_order_subframes = 0;
        int32_t reorder_max_lateness_s = 0;
    };

    using PageCallback =
        std::function<bool(const Page& page)>;

public:
    /*
        Read a JSONL file and call callback once per decoded E1-B page.

        raw_to_word_bit_offset:
            1 for current OSNMAlib.eu raw page interpretation.

        Returns false only for file-open failure or callback abort.
        Malformed lines/pages are counted and skipped.
    */
    static bool ReadFile(const char* filename,
        PageCallback callback,
        Stats* stats = nullptr,
        int32_t raw_to_word_bit_offset = 1);

    /*
        Convenience bridge for quick testing:
            JSONL file -> E1-B pages -> OsnmaAuthenticator::FeedRawInavPage()

        The raw JSON page is split into two internal 128-bit software buffers:
            even_128b starts at raw bit 1
            odd_128b  starts at raw bit 121

        The odd buffer contains only the available 119 bits; the remaining bits
        stay zero.
    */
    static bool FeedFileToAuthenticator(const char* filename,
        OsnmaAuthenticator& authenticator,
        Stats* stats = nullptr,
        NavSignalSource source = NavSignalSource::Unknown,
        int32_t native_source_code = 0,
        bool crc_ok = true,
        int32_t raw_to_word_bit_offset = 1);

private:
    static bool ParseLine(const std::string& line,
        PageCallback callback,
        Stats& stats,
        int32_t raw_to_word_bit_offset);

    static bool HexToBytes(const std::string& hex,
        std::uint8_t* out,
        int32_t out_size_bytes);

    static bool CopyBitsMsb0Shifted(const std::uint8_t* src,
        int32_t src_bit_offset,
        int32_t src_bit_capacity,
        std::uint8_t* dst,
        int32_t dst_bit_count);

    static bool GetBitMsb0(const std::uint8_t* data,
        int32_t bit_index);

    static void SetBitMsb0(std::uint8_t* data,
        int32_t bit_index,
        bool value);
};
