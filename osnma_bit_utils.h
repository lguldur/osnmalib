#pragma once

#include <cstdint>

inline bool GetBitMsb0(const std::uint8_t* data, int32_t bit_index)
{
    const std::uint8_t byte_value = data[bit_index / 8];
    const int32_t bit_in_byte = bit_index % 8;

    return ((byte_value >> (7 - bit_in_byte)) & 0x01u) != 0;
}

inline int32_t GetUnsignedBitsMsb0(const std::uint8_t* data,
    int32_t first_bit,
    int32_t bit_count)
{
    if (data == nullptr)
        return 0;

    if (bit_count <= 0 || bit_count > 31)
        return 0;

    int32_t value = 0;

    for (int32_t i = 0; i < bit_count; ++i)
    {
        value <<= 1;

        if (GetBitMsb0(data, first_bit + i))
            value |= 1;
    }

    return value;
}

inline void CopyBitsMsb0(const std::uint8_t* data,
    int32_t first_bit,
    int32_t bit_count,
    std::uint8_t* out_data,
    int32_t out_byte_count)
{
    for (int32_t i = 0; i < out_byte_count; ++i)
        out_data[i] = std::uint8_t{ 0 };

    if (data == nullptr || out_data == nullptr)
        return;

    if (bit_count <= 0 || out_byte_count <= 0)
        return;

    for (int32_t i = 0; i < bit_count; ++i)
    {
        if (!GetBitMsb0(data, first_bit + i))
            continue;

        const int32_t out_bit = i;
        const int32_t out_byte = out_bit / 8;
        const int32_t out_bit_in_byte = out_bit % 8;

        if (out_byte >= out_byte_count)
            break;

        std::uint8_t v = out_data[out_byte];
        v |= static_cast<std::uint8_t>(1u << (7 - out_bit_in_byte));
        out_data[out_byte] = v;
    }
}
