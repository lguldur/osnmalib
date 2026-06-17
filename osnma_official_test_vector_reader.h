#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "gnss_time.h"
#include "nav_signal_source.h"
#include "osnma_authenticator.h"
#include "osnma_raw_json_reader.h"

class OsnmaOfficialTestVectorReader
{
public:
    static constexpr int32_t RAW_PAGE_BITS = OsnmaRawJsonReader::RAW_PAGE_BITS;
    static constexpr int32_t RAW_PAGE_BYTES = OsnmaRawJsonReader::RAW_PAGE_BYTES;

    static constexpr int32_t OSNMA_WORD_BITS = OsnmaRawJsonReader::OSNMA_WORD_BITS;
    static constexpr int32_t OSNMA_WORD_BYTES = OsnmaRawJsonReader::OSNMA_WORD_BYTES;

    struct Page
    {
        int32_t prn = -1;
        int32_t page_index = -1;
        int32_t global_page_index = -1;

        GnssTime page_time{};

        std::array<std::uint8_t, RAW_PAGE_BYTES> raw_240b{};
        std::array<std::uint8_t, OSNMA_WORD_BYTES> even_128b{};
        std::array<std::uint8_t, OSNMA_WORD_BYTES> odd_128b{};
    };

    struct Stats
    {
        int32_t csv_row_count = 0;
        int32_t satellite_count = 0;
        int32_t page_count_per_satellite = 0;
        int32_t page_count = 0;

        int32_t malformed_row_count = 0;
        int32_t malformed_hex_count = 0;
        int32_t inconsistent_length_count = 0;

        int32_t fed_page_count = 0;

        GnssTime start_time{};
        bool has_start_time = false;

        std::array<int32_t, 64> wt_count{};
    };

    using PageCallback =
        std::function<bool(const Page& page)>;

public:
    /*
        Read an official Galileo OSNMA test-vector CSV directly.

        Expected CSV format:
            SVID,NumNavBits,NavBitsHEX
            02,432000,<continuous hex nav bit stream>

        The filename is used to infer the start GST when possible, for example:
            16_AUG_2023_GST_05_00_01.csv

        Pages are emitted in chronological order:
            page 0 for all SVIDs, page 1 for all SVIDs, ...

        raw_to_word_bit_offset:
            1 for the same 240-bit E1-B page interpretation as OsnmaRawJsonReader.
    */
    static bool ReadFile(const char* filename,
        PageCallback callback,
        Stats* stats = nullptr,
        int32_t raw_to_word_bit_offset = 1);

    /*
        Convenience bridge:
            official CSV -> E1-B pages -> OsnmaAuthenticator::FeedRawInavPage()
    */
    static bool FeedFileToAuthenticator(const char* filename,
        OsnmaAuthenticator& authenticator,
        Stats* stats = nullptr,
        NavSignalSource source = NavSignalSource::Unknown,
        int32_t native_source_code = 0,
        bool crc_ok = true,
        int32_t raw_to_word_bit_offset = 1);

    /*
        Exposed for diagnostics/tests. Returns false if the filename does not
        contain the expected DD_MON_YYYY_GST_HH_MM_SS pattern.
    */
    static bool TryParseStartTimeFromFilename(const char* filename,
        GnssTime& start_time_out);

private:
    struct SatelliteStream
    {
        int32_t prn = -1;
        int32_t num_nav_bits = 0;
        std::string nav_bits_hex;
    };

private:
    static bool ParseCsvRow(const std::string& line,
        SatelliteStream& stream_out);

    static bool DecodePage(const SatelliteStream& stream,
        int32_t global_page_index,
        const GnssTime& start_time,
        int32_t raw_to_word_bit_offset,
        Page& page_out);

    static bool HexToBytes(const char* hex,
        int32_t hex_char_count,
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

    static int32_t GetUnsignedBitsMsb0(const std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count);

    static bool AdvanceTime(const GnssTime& start_time,
        double seconds,
        GnssTime& out);

    static bool MonthFromString(const std::string& month,
        int32_t& month_out);

    static std::int64_t DaysFromCivil(int32_t year,
        int32_t month,
        int32_t day);
};
