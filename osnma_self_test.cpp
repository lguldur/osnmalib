#include "osnma_self_test.h"

#include <cmath>
#include <cstring>
#include <numbers>
#include <vector>

#include "galileo_auth_data_fifo.h"
#include "galileo_nav_candidate.h"
#include "osnma_crypto.h"
#include "osnma_mac_input.h"
#include "osnma_mac_verifier.h"
#include "osnma_mack.h"
#include "osnma_tesla_chain.h"

namespace
{
    static GnssTime MakeTestTime()
    {
        GnssTime t{};
        t.wn = 1234;
        t.tow = 345630.0;
        return t;
    }

    static std::uint32_t MakeGstSf32(const GnssTime& time)
    {
        const std::uint32_t wn =
            static_cast<std::uint32_t>(time.wn) & 0x0FFFu;

        const std::uint32_t tow =
            static_cast<std::uint32_t>(time.tow) & 0x000FFFFFu;

        return (wn << 20) | tow;
    }

    static void StoreGst32(const GnssTime& time,
        std::uint8_t out[4])
    {
        const std::uint32_t value =
            MakeGstSf32(time);

        out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
        out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
        out[3] = static_cast<std::uint8_t>(value & 0xFFu);
    }

    static void StoreAlpha48(std::uint64_t alpha,
        std::uint8_t out[6])
    {
        const std::uint64_t v =
            alpha & 0x0000FFFFFFFFFFFFull;

        out[0] = static_cast<std::uint8_t>((v >> 40) & 0xFFu);
        out[1] = static_cast<std::uint8_t>((v >> 32) & 0xFFu);
        out[2] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
        out[3] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
        out[4] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
        out[5] = static_cast<std::uint8_t>(v & 0xFFu);
    }

    static void SetBitsMsb0(std::uint8_t* data,
        int32_t first_bit,
        int32_t bit_count,
        std::uint32_t value)
    {
        if (data == nullptr || bit_count <= 0 || bit_count > 32)
            return;

        for (int32_t i = 0; i < bit_count; ++i)
        {
            const int32_t src_shift =
                bit_count - 1 - i;

            const bool bit =
                ((value >> src_shift) & 0x01u) != 0;

            const int32_t bit_index =
                first_bit + i;

            const int32_t byte_index =
                bit_index / 8;

            const int32_t bit_in_byte =
                bit_index % 8;

            const std::uint8_t mask =
                static_cast<std::uint8_t>(0x80u >> bit_in_byte);

            if (bit)
                data[byte_index] |= mask;
            else
                data[byte_index] &= static_cast<std::uint8_t>(~mask);
        }
    }

    static void FillWord(GalileoNavCandidate& candidate,
        int32_t wt,
        std::uint8_t pattern)
    {
        GalileoNavWord& word = candidate.words[wt];

        word = GalileoNavWord{};
        word.wt = wt;
        word.valid = true;

        word.page_epoch = MakeTestTime();
        word.has_epoch = true;

        for (int32_t i = 0; i < GAL_INAV_BYTES; ++i)
        {
            word.even[i] =
                static_cast<std::uint8_t>(pattern + i);

            word.odd[i] =
                static_cast<std::uint8_t>(0xA0u + pattern + i);
        }
    }

    static GalileoNavCandidate MakeCedCandidate()
    {
        GalileoNavCandidate candidate{};

        candidate.prn = 7;
        candidate.iod = 11;
        candidate.toe = 22;
        candidate.creation_time = MakeTestTime();
        candidate.last_update_time = MakeTestTime();

        FillWord(candidate, GAL_WT1, 0x10);
        FillWord(candidate, GAL_WT2, 0x20);
        FillWord(candidate, GAL_WT3, 0x30);
        FillWord(candidate, GAL_WT4, 0x40);
        FillWord(candidate, GAL_WT5, 0x50);

        candidate.complete = candidate.IsComplete();

        return candidate;
    }

    static GalileoNavCandidate MakeTimingCandidate()
    {
        GalileoNavCandidate candidate{};

        candidate.prn = 7;
        candidate.iod = -1;
        candidate.toe = -1;
        candidate.creation_time = MakeTestTime();
        candidate.last_update_time = MakeTestTime();

        FillWord(candidate, GAL_WT6, 0x60);
        FillWord(candidate, GAL_WT10, 0x70);

        candidate.words[GAL_WT6].page_epoch = MakeTestTime();
        candidate.words[GAL_WT6].has_epoch = true;

        candidate.words[GAL_WT10].page_epoch = MakeTestTime();
        candidate.words[GAL_WT10].page_epoch.tow += 120.0;
        candidate.words[GAL_WT10].has_epoch = true;

        return candidate;
    }

    static GalileoNavCandidate MakeIncompleteCedCandidate()
    {
        GalileoNavCandidate candidate{};

        candidate.prn = 7;
        candidate.iod = 11;
        candidate.toe = 22;
        candidate.creation_time = MakeTestTime();
        candidate.last_update_time = MakeTestTime();

        FillWord(candidate, GAL_WT1, 0x10);

        candidate.complete = candidate.IsComplete();

        return candidate;
    }

    static GalileoNavCandidate MakeIncompleteTimingCandidate()
    {
        GalileoNavCandidate candidate{};

        candidate.prn = 7;
        candidate.iod = -1;
        candidate.toe = -1;
        candidate.creation_time = MakeTestTime();
        candidate.last_update_time = MakeTestTime();

        FillWord(candidate, GAL_WT6, 0x60);

        candidate.words[GAL_WT6].page_epoch = MakeTestTime();
        candidate.words[GAL_WT6].has_epoch = true;

        return candidate;
    }

    static OsnmaMackMessage MakeBaseMack()
    {
        OsnmaMackMessage mack{};

        mack.prn = 7;
        mack.subframe_epoch = MakeTestTime();

        mack.key_size_bits = 128;
        mack.key_size_bytes = 16;

        mack.tag_size_bits = 40;
        mack.tag_size_bytes = 5;

        mack.total_tag_count = 6;
        mack.tag_info_count = 5;

        mack.macseq = 0x123;
        mack.cop = 1;

        mack.valid_layout = true;

        return mack;
    }

    static OsnmaMackTagInfo MakeTagInfo(int32_t index,
        int32_t prnd,
        OsnmaAdkd adkd,
        int32_t cop)
    {
        OsnmaMackTagInfo tag{};

        tag.index = index;

        tag.tag_size_bits = 40;
        tag.tag_size_bytes = 5;

        tag.prnd = prnd;
        tag.adkd = adkd;
        tag.cop = cop;

        tag.valid_info = true;

        return tag;
    }

    static bool CheckHeader(const std::vector<std::uint8_t>& msg,
        std::uint8_t expected_prnd,
        std::uint8_t expected_prna,
        std::uint8_t expected_ctr,
        std::uint8_t expected_nmas)
    {
        if (msg.size() < 8)
            return false;

        const std::uint32_t gst =
            MakeGstSf32(MakeTestTime());

        if (msg[0] != expected_prnd)
            return false;

        if (msg[1] != expected_prna)
            return false;

        if (msg[2] != static_cast<std::uint8_t>((gst >> 24) & 0xFFu))
            return false;

        if (msg[3] != static_cast<std::uint8_t>((gst >> 16) & 0xFFu))
            return false;

        if (msg[4] != static_cast<std::uint8_t>((gst >> 8) & 0xFFu))
            return false;

        if (msg[5] != static_cast<std::uint8_t>(gst & 0xFFu))
            return false;

        if (msg[6] != expected_ctr)
            return false;

        /*
            After:
                PRND   8 bits
                PRNA   8 bits
                GST_SF 32 bits
                CTR    8 bits

            NMAS starts at byte 7, bits 7..6.
        */
        const std::uint8_t nmas_high =
            static_cast<std::uint8_t>((expected_nmas & 0x03u) << 6);

        if ((msg[7] & 0xC0u) != nmas_high)
            return false;

        return true;
    }

    static bool BuildSyntheticTeslaKrootSha256(OsnmaDsmKroot& kroot,
        OsnmaMackMessage& mack,
        bool wrong_disclosed_key)
    {
        kroot = OsnmaDsmKroot{};
        mack = OsnmaMackMessage{};

        /*
            InitializeFromKroot() internally shifts KROOT GST by -30 s.

            Therefore:
                kroot GST       = WN 2000, TOW 36000
                root key time   = WN 2000, TOW 35970
                disclosed K1 at = WN 2000, TOW 36000
        */
        const int32_t wn = 2000;
        const double kroot_tow_s = 36000.0;
        const int32_t kroot_towh = 10;

        GnssTime root_time{};
        root_time.wn = wn;
        root_time.tow = kroot_tow_s - 30.0;

        GnssTime disclosed_time{};
        disclosed_time.wn = wn;
        disclosed_time.tow = kroot_tow_s;

        const std::uint64_t alpha =
            0x0000010203040506ull;

        std::uint8_t disclosed_key[16]{};

        for (int32_t i = 0; i < 16; ++i)
        {
            disclosed_key[i] =
                static_cast<std::uint8_t>(0xA0u + i);
        }

        std::uint8_t hash_input[16 + 4 + 6]{};
        int32_t hash_input_size = 0;

        std::memcpy(hash_input + hash_input_size,
            disclosed_key,
            16);

        hash_input_size += 16;

        std::uint8_t gst_bytes[4]{};
        StoreGst32(root_time, gst_bytes);

        std::memcpy(hash_input + hash_input_size,
            gst_bytes,
            4);

        hash_input_size += 4;

        std::uint8_t alpha_bytes[6]{};
        StoreAlpha48(alpha, alpha_bytes);

        std::memcpy(hash_input + hash_input_size,
            alpha_bytes,
            6);

        hash_input_size += 6;

        std::uint8_t digest[32]{};

        if (!OsnmaSha256(hash_input,
            hash_input_size,
            digest))
        {
            return false;
        }

        kroot.valid_layout = true;
        kroot.hash_function = OsnmaHashFunction::Sha256;
        kroot.mac_function = OsnmaMacFunction::HmacSha256;

        kroot.key_size_bits = 128;
        kroot.tag_size_bits = 40;
        kroot.mac_lookup_table = 34;

        kroot.kroot_wn = wn;
        kroot.kroot_towh = kroot_towh;

        kroot.alpha = alpha;

        kroot.kroot_size_bytes = 16;

        /*
            K0 = trunc_128(SHA256(K1 || GST0 || alpha))
        */
        for (int32_t i = 0; i < 16; ++i)
            kroot.kroot[i] = digest[i];

        mack.valid_layout = true;
        mack.prn = 7;
        mack.subframe_epoch = disclosed_time;

        mack.key_size_bits = 128;
        mack.key_size_bytes = 16;

        mack.tag_size_bits = 40;
        mack.tag_size_bytes = 5;

        for (int32_t i = 0; i < 16; ++i)
            mack.disclosed_key[i] = disclosed_key[i];

        if (wrong_disclosed_key)
            mack.disclosed_key[0] ^= 0x01u;

        return true;
    }

    static bool BuildMacseqTestChainAndMack(OsnmaTeslaChain& chain,
        OsnmaMackMessage& tag_mack,
        bool store_future_key,
        bool wrong_macseq)
    {
        OsnmaDsmKroot kroot{};
        OsnmaMackMessage disclosed_mack{};

        if (!BuildSyntheticTeslaKrootSha256(kroot,
            disclosed_mack,
            false))
        {
            return false;
        }

        AuthReason reason = AuthReason::None;

        if (!chain.InitializeFromKroot(kroot,
            reason))
        {
            return false;
        }

        if (store_future_key)
        {
            if (!chain.VerifyAndStoreDisclosedKey(disclosed_mack,
                reason))
            {
                return false;
            }
        }

        /*
            The MACK to verify is at root time, therefore its authentication
            key is K1, disclosed one subframe later.
        */
        tag_mack = OsnmaMackMessage{};

        tag_mack.valid_layout = true;
        tag_mack.prn = 7;

        tag_mack.subframe_epoch.wn = 2000;
        tag_mack.subframe_epoch.tow = 35970.0;

        tag_mack.key_size_bits = 128;
        tag_mack.key_size_bytes = 16;

        tag_mack.tag_size_bits = 40;
        tag_mack.tag_size_bytes = 5;

        tag_mack.total_tag_count = 6;
        tag_mack.tag_info_count = 5;

        tag_mack.cop = 1;

        /*
            MACLT 34, GST row 1 at TOW 35970:
                slot 1 is FLX.

            Give that FLX slot a raw 16-bit Tag-Info field:
                PRND = 0x11
                ADKD = 12
                COP  = 1

            BuildMacseqInput() must copy exactly these two bytes.
        */
        static constexpr int32_t TAG_SIZE_BITS = 40;
        static constexpr int32_t TAG_AND_INFO_BITS = 56;
        static constexpr int32_t FLX_TAG_NUMBER = 1;

        const int32_t tag_info_start =
            FLX_TAG_NUMBER * TAG_AND_INFO_BITS + TAG_SIZE_BITS;

        SetBitsMsb0(tag_mack.raw.data(),
            tag_info_start,
            16,
            0x11C1u);

        /*
            MACSEQ input:
                PRNA || GST_SF || raw Tag-Info of FLX slots
        */
        std::vector<std::uint8_t> macseq_input;

        macseq_input.push_back(static_cast<std::uint8_t>(tag_mack.prn));

        std::uint8_t gst_bytes[4]{};
        
        StoreGst32(tag_mack.subframe_epoch,
            gst_bytes);

        macseq_input.push_back(gst_bytes[0]);
        macseq_input.push_back(gst_bytes[1]);
        macseq_input.push_back(gst_bytes[2]);
        macseq_input.push_back(gst_bytes[3]);

        macseq_input.push_back(0x11u);
        macseq_input.push_back(0xC1u);

        std::uint8_t computed[2]{};

        /*
            The future key K1 is known from disclosed_mack.
        */
        if (!OsnmaHmacSha256(disclosed_mack.disclosed_key.data(),
            disclosed_mack.key_size_bytes,
            macseq_input.data(),
            static_cast<int32_t>(macseq_input.size()),
            computed,
            2))
        {
            return false;
        }

        tag_mack.macseq =
            (static_cast<int32_t>(computed[0]) << 4) |
            static_cast<int32_t>((computed[1] >> 4) & 0x0Fu);

        if (wrong_macseq)
            tag_mack.macseq ^= 0x001;

        return true;
    }
}


bool OsnmaSelfTest::TestAuthenticatedCedDecode(Result& result)
{
    ++result.test_count;

    GalileoNavCandidate candidate{};
    candidate.prn = 7;
    candidate.creation_time = MakeTestTime();
    candidate.last_update_time = MakeTestTime();

    for (int32_t wt = GAL_WT1; wt <= GAL_WT5; ++wt)
    {
        FillWord(candidate, wt, 0);
        candidate.words[wt].even.fill(0);
        SetBitsMsb0(candidate.words[wt].even.data(), 0, 6,
            static_cast<std::uint32_t>(wt));
        SetBitsMsb0(candidate.words[wt].even.data(), 6, 10, 42u);
    }

    // WT1
    SetBitsMsb0(candidate.words[GAL_WT1].even.data(), 16, 14, 100u);
    SetBitsMsb0(candidate.words[GAL_WT1].even.data(), 30, 32, 0x40000000u);
    SetBitsMsb0(candidate.words[GAL_WT1].even.data(), 62, 32, 0x40000000u);
    SetBitsMsb0(candidate.words[GAL_WT1].even.data(), 94, 32, 0x80000000u);

    // WT2
    SetBitsMsb0(candidate.words[GAL_WT2].even.data(), 16, 32, 0x20000000u);
    SetBitsMsb0(candidate.words[GAL_WT2].even.data(), 48, 32, 0x10000000u);
    SetBitsMsb0(candidate.words[GAL_WT2].even.data(), 80, 32, 0xE0000000u);
    SetBitsMsb0(candidate.words[GAL_WT2].even.data(), 112, 14, 0x3FFFu);

    // WT3
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 16, 24, 1u);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 40, 16, 0xFFFFu);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 56, 16, 2u);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 72, 16, 0xFFFEu);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 88, 16, 32u);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 104, 16, 0xFFE0u);
    SetBitsMsb0(candidate.words[GAL_WT3].even.data(), 120, 8, 33u);

    // WT4
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 16, 6, 7u);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 22, 16, 1u);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 38, 16, 0xFFFFu);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 54, 14, 101u);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 68, 31, 1u);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 99, 21, 0x1FFFFFu);
    SetBitsMsb0(candidate.words[GAL_WT4].even.data(), 120, 6, 1u);

    // WT5 (WT5 does not carry IODnav, overwrite the artificial field above)
    candidate.words[GAL_WT5].even.fill(0);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 0, 6, 5u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 6, 11, 4u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 17, 11, 0x7FEu);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 28, 14, 3u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 42, 5, 0x15u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 47, 10, 1u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 57, 10, 0x3FFu);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 67, 2, 2u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 69, 2, 1u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 71, 1, 1u);
    SetBitsMsb0(candidate.words[GAL_WT5].even.data(), 72, 1, 0u);

    candidate.complete = candidate.IsComplete();

    GalileoAuthenticatedCedStatus decoded{};

    const bool ok = GalileoInavDecoder::DecodeCedStatus(
        candidate,
        MakeTestTime(),
        MakeTestTime(),
        40,
        123u,
        NavSignalSource::Freq1,
        99,
        decoded);

    if (!Check(result, ok, "authenticated CED decode failed"))
        return false;

    if (!Check(result, decoded.ephemeris_valid,
        "authenticated ephemeris validity failed"))
    {
        return false;
    }

    if (!Check(result, decoded.iodnav == 42,
        "authenticated IODnav decode failed"))
    {
        return false;
    }

    if (!Check(result, decoded.ephemeris.Toe == 6000,
        "authenticated Toe decode failed"))
    {
        return false;
    }

    if (!Check(result,
        std::fabs(decoded.ephemeris.M0 - 0.5 * std::numbers::pi_v<double>) < 1e-12,
        "authenticated M0 decode failed"))
    {
        return false;
    }

    if (!Check(result,
        std::fabs(decoded.ephemeris.Ecc - 0.125) < 1e-15,
        "authenticated eccentricity decode failed"))
    {
        return false;
    }

    if (!Check(result,
        std::fabs(decoded.ephemeris.sqrtA - 4096.0) < 1e-12,
        "authenticated sqrtA decode failed"))
    {
        return false;
    }

    if (!Check(result, decoded.sisa == 33,
        "authenticated SISA decode failed"))
    {
        return false;
    }

    if (!Check(result, decoded.ephemeris.DataSources == 513u,
        "authenticated RINEX data-source decode failed"))
    {
        return false;
    }

    // E1-B DVS=0, E1-B SHS=1, E5b DVS=1, E5b SHS=2.
    // RINEX bits: (1 << 1) + (1 << 6) + (2 << 7) = 322.
    if (!Check(result, decoded.ephemeris.SVHealth == 322u,
        "authenticated RINEX health packing failed"))
    {
        return false;
    }

    if (!Check(result,
        decoded.wt1_page_time.wn == MakeTestTime().wn &&
        std::fabs(decoded.wt1_page_time.tow - MakeTestTime().tow) < 1e-12,
        "authenticated WT1 page time was not preserved"))
    {
        return false;
    }

    if (!Check(result,
        std::fabs(decoded.ionosphere.ai0 - 1.0) < 1e-15,
        "authenticated ionosphere ai0 decode failed"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestAuthenticatedTimingDecode(Result& result)
{
    ++result.test_count;

    GalileoNavCandidate candidate{};
    candidate.prn = 7;
    candidate.creation_time = MakeTestTime();
    candidate.last_update_time = MakeTestTime();

    FillWord(candidate, GAL_WT6, 0);
    FillWord(candidate, GAL_WT10, 0);
    candidate.words[GAL_WT6].even.fill(0);
    candidate.words[GAL_WT10].even.fill(0);

    candidate.words[GAL_WT6].page_epoch = MakeTestTime();
    candidate.words[GAL_WT10].page_epoch = MakeTestTime();

    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 0, 6, 6u);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 6, 32, 1u);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 38, 24, 0xFFFFFEu);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 62, 8, 18u);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 70, 8, 12u);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 78, 8,
        static_cast<std::uint32_t>(MakeTestTime().wn & 0xFF));
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 86, 8,
        static_cast<std::uint32_t>((MakeTestTime().wn + 1) & 0xFF));
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 94, 3, 3u);
    SetBitsMsb0(candidate.words[GAL_WT6].even.data(), 97, 8, 19u);

    SetBitsMsb0(candidate.words[GAL_WT10].even.data(), 0, 6, 10u);
    SetBitsMsb0(candidate.words[GAL_WT10].even.data(), 86, 16, 1u);
    SetBitsMsb0(candidate.words[GAL_WT10].even.data(), 102, 12, 0xFFEu);
    SetBitsMsb0(candidate.words[GAL_WT10].even.data(), 114, 8, 4u);
    SetBitsMsb0(candidate.words[GAL_WT10].even.data(), 122, 6,
        static_cast<std::uint32_t>(MakeTestTime().wn & 0x3F));

    GalileoAuthenticatedTiming decoded{};

    const bool ok = GalileoInavDecoder::DecodeTiming(
        candidate,
        MakeTestTime(),
        MakeTestTime(),
        40,
        456u,
        NavSignalSource::Freq1,
        99,
        decoded);

    if (!Check(result, ok, "authenticated timing decode failed"))
        return false;

    if (!Check(result, decoded.utc_valid && decoded.ggto_valid,
        "authenticated timing validity failed"))
    {
        return false;
    }

    if (!Check(result, decoded.utc.DeltaT_LS == 18,
        "authenticated UTC leap seconds decode failed"))
    {
        return false;
    }

    if (!Check(result, decoded.utc.T0_UTC == 43200,
        "authenticated UTC t0 decode failed"))
    {
        return false;
    }

    if (!Check(result, decoded.t0g == 14400,
        "authenticated GGTO t0 decode failed"))
    {
        return false;
    }

    return true;
}

OsnmaSelfTest::Result OsnmaSelfTest::RunAll()
{
    Result result{};

    TestTag0Adkd0LengthAndHeader(result);
    TestTagInfoAdkd0LengthAndCtr(result);
    TestTagInfoAdkd4LengthAndCtr(result);
    TestMissingCedDataFails(result);
    TestMissingTimingDataFails(result);
    TestTeslaSha256OneStepAcceptsValidKey(result);
    TestTeslaSha256OneStepRejectsWrongKey(result);
    TestMacseqValidThenMissingNavData(result);
    TestMacseqRejectsWrongMacseq(result);
    TestMacseqWaitsForFutureKey(result);
    TestAuthenticatedCedDecode(result);
    TestAuthenticatedTimingDecode(result);

    return result;
}

static bool CheckTag0Header(const std::vector<std::uint8_t>& msg,
    std::uint8_t expected_prna,
    std::uint8_t expected_ctr,
    std::uint8_t expected_nmas)
{
    if (msg.size() < 7)
        return false;

    const std::uint32_t gst =
        MakeGstSf32(MakeTestTime());

    if (msg[0] != expected_prna)
        return false;

    if (msg[1] != static_cast<std::uint8_t>((gst >> 24) & 0xFFu))
        return false;

    if (msg[2] != static_cast<std::uint8_t>((gst >> 16) & 0xFFu))
        return false;

    if (msg[3] != static_cast<std::uint8_t>((gst >> 8) & 0xFFu))
        return false;

    if (msg[4] != static_cast<std::uint8_t>(gst & 0xFFu))
        return false;

    if (msg[5] != expected_ctr)
        return false;

    /*
        Tag0 header:
            PRNA   8 bits
            GST_SF 32 bits
            CTR    8 bits

        NMAS starts at byte 6, bits 7..6.
    */
    const std::uint8_t nmas_high =
        static_cast<std::uint8_t>((expected_nmas & 0x03u) << 6);

    if ((msg[6] & 0xC0u) != nmas_high)
        return false;

    return true;
}

bool OsnmaSelfTest::TestTag0Adkd0LengthAndHeader(Result& result)
{
    ++result.test_count;

    const GalileoNavCandidate candidate =
        MakeCedCandidate();

    OsnmaMackMessage mack =
        MakeBaseMack();

    std::vector<std::uint8_t> msg;

    const bool ok =
        OsnmaMacInputBuilder::BuildTag0Message(mack,
            candidate,
            2,
            msg);

    if (!Check(result, ok, "Tag0 ADKD0 message build failed"))
        return false;

    if (!Check(result,
        msg.size() == 75,
        "Tag0 ADKD0 message size is not 75 bytes"))
    {
        return false;
    }

    if (!Check(result,
        CheckTag0Header(msg, 7, 1, 2),
        "Tag0 ADKD0 header mismatch"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestTagInfoAdkd0LengthAndCtr(Result& result)
{
    ++result.test_count;

    const GalileoNavCandidate candidate =
        MakeCedCandidate();

    OsnmaMackMessage mack =
        MakeBaseMack();

    const OsnmaMackTagInfo tag =
        MakeTagInfo(3,
            12,
            OsnmaAdkd::InavCed,
            1);

    std::vector<std::uint8_t> msg;

    const bool ok =
        OsnmaMacInputBuilder::BuildTagMessage(mack,
            tag,
            candidate,
            1,
            msg);

    if (!Check(result, ok, "Tag-Info ADKD0 message build failed"))
        return false;

    if (!Check(result,
        msg.size() == 76,
        "Tag-Info ADKD0 message size is not 76 bytes"))
    {
        return false;
    }

    if (!Check(result,
        CheckHeader(msg, 12, 7, 4, 1),
        "Tag-Info ADKD0 header or CTR mismatch"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestTagInfoAdkd4LengthAndCtr(Result& result)
{
    ++result.test_count;

    const GalileoNavCandidate candidate =
        MakeTimingCandidate();

    OsnmaMackMessage mack =
        MakeBaseMack();

    const OsnmaMackTagInfo tag =
        MakeTagInfo(1,
            7,
            OsnmaAdkd::InavTiming,
            1);

    std::vector<std::uint8_t> msg;

    const bool ok =
        OsnmaMacInputBuilder::BuildTagMessage(mack,
            tag,
            candidate,
            3,
            msg);

    if (!Check(result, ok, "Tag-Info ADKD4 message build failed"))
        return false;

    if (!Check(result,
        msg.size() == 25,
        "Tag-Info ADKD4 message size is not 25 bytes"))
    {
        return false;
    }

    if (!Check(result,
        CheckHeader(msg, 7, 7, 2, 3),
        "Tag-Info ADKD4 header or CTR mismatch"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestMissingCedDataFails(Result& result)
{
    ++result.test_count;

    const GalileoNavCandidate candidate =
        MakeIncompleteCedCandidate();

    OsnmaMackMessage mack =
        MakeBaseMack();

    std::vector<std::uint8_t> msg;

    const bool ok =
        OsnmaMacInputBuilder::BuildTag0Message(mack,
            candidate,
            0,
            msg);

    if (!Check(result,
        !ok,
        "Tag0 ADKD0 unexpectedly succeeded with incomplete CED data"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestMissingTimingDataFails(Result& result)
{
    ++result.test_count;

    const GalileoNavCandidate candidate =
        MakeIncompleteTimingCandidate();

    OsnmaMackMessage mack =
        MakeBaseMack();

    const OsnmaMackTagInfo tag =
        MakeTagInfo(1,
            7,
            OsnmaAdkd::InavTiming,
            1);

    std::vector<std::uint8_t> msg;

    const bool ok =
        OsnmaMacInputBuilder::BuildTagMessage(mack,
            tag,
            candidate,
            0,
            msg);

    if (!Check(result,
        !ok,
        "ADKD4 unexpectedly succeeded with incomplete timing data"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestTeslaSha256OneStepAcceptsValidKey(Result& result)
{
    ++result.test_count;

    OsnmaDsmKroot kroot{};
    OsnmaMackMessage mack{};

    if (!Check(result,
        BuildSyntheticTeslaKrootSha256(kroot,
            mack,
            false),
        "TESLA SHA256 test-vector construction failed"))
    {
        return false;
    }

    OsnmaTeslaChain chain{};
    AuthReason reason = AuthReason::None;

    if (!Check(result,
        chain.InitializeFromKroot(kroot,
            reason),
        "TESLA SHA256 InitializeFromKroot failed"))
    {
        return false;
    }

    if (!Check(result,
        chain.VerifyAndStoreDisclosedKey(mack,
            reason),
        "TESLA SHA256 valid disclosed key rejected"))
    {
        return false;
    }

    if (!Check(result,
        chain.HasKey(1),
        "TESLA SHA256 valid disclosed key was not stored at index 1"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestTeslaSha256OneStepRejectsWrongKey(Result& result)
{
    ++result.test_count;

    OsnmaDsmKroot kroot{};
    OsnmaMackMessage mack{};

    if (!Check(result,
        BuildSyntheticTeslaKrootSha256(kroot,
            mack,
            true),
        "TESLA SHA256 wrong-key test-vector construction failed"))
    {
        return false;
    }

    OsnmaTeslaChain chain{};
    AuthReason reason = AuthReason::None;

    if (!Check(result,
        chain.InitializeFromKroot(kroot,
            reason),
        "TESLA SHA256 wrong-key InitializeFromKroot failed"))
    {
        return false;
    }

    const bool accepted =
        chain.VerifyAndStoreDisclosedKey(mack,
            reason);

    if (!Check(result,
        !accepted,
        "TESLA SHA256 wrong disclosed key was accepted"))
    {
        return false;
    }

    if (!Check(result,
        !chain.HasKey(1),
        "TESLA SHA256 wrong disclosed key was stored"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestMacseqValidThenMissingNavData(Result& result)
{
    ++result.test_count;

    OsnmaTeslaChain chain{};
    OsnmaMackMessage mack{};

    if (!Check(result,
        BuildMacseqTestChainAndMack(chain,
            mack,
            true,
            false),
        "MACSEQ valid test-vector construction failed"))
    {
        return false;
    }

    GalileoNavCandidateStore nav_store{};
    OsnmaMacVerifier verifier{};

    const OsnmaMacVerifier::Result verify_result =
        verifier.Verify(mack,
            nav_store,
            chain,
            OsnmaMacFunction::HmacSha256,
            0,
            mack.subframe_epoch);

    if (!Check(result,
        verify_result.state == AuthState::Unknown,
        "MACSEQ valid test unexpectedly authenticated without navdata"))
    {
        return false;
    }

    if (!Check(result,
        verify_result.reason == AuthReason::MissingNavData,
        "MACSEQ valid test did not reach MissingNavData"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestMacseqRejectsWrongMacseq(Result& result)
{
    ++result.test_count;

    OsnmaTeslaChain chain{};
    OsnmaMackMessage mack{};

    if (!Check(result,
        BuildMacseqTestChainAndMack(chain,
            mack,
            true,
            true),
        "MACSEQ wrong test-vector construction failed"))
    {
        return false;
    }

    GalileoNavCandidateStore nav_store{};
    OsnmaMacVerifier verifier{};

    const OsnmaMacVerifier::Result verify_result =
        verifier.Verify(mack,
            nav_store,
            chain,
            OsnmaMacFunction::HmacSha256,
            0,
            mack.subframe_epoch);

    if (!Check(result,
        verify_result.state == AuthState::Unknown,
        "MACSEQ wrong test unexpectedly authenticated"))
    {
        return false;
    }

    if (!Check(result,
        verify_result.reason == AuthReason::MackVerificationFailed,
        "MACSEQ wrong test did not fail with MackVerificationFailed"))
    {
        return false;
    }

    return true;
}

bool OsnmaSelfTest::TestMacseqWaitsForFutureKey(Result& result)
{
    ++result.test_count;

    OsnmaTeslaChain chain{};
    OsnmaMackMessage mack{};

    if (!Check(result,
        BuildMacseqTestChainAndMack(chain,
            mack,
            false,
            false),
        "MACSEQ waiting-key test-vector construction failed"))
    {
        return false;
    }

    GalileoNavCandidateStore nav_store{};
    OsnmaMacVerifier verifier{};

    const OsnmaMacVerifier::Result verify_result =
        verifier.Verify(mack,
            nav_store,
            chain,
            OsnmaMacFunction::HmacSha256,
            0,
            mack.subframe_epoch);

    if (!Check(result,
        verify_result.state == AuthState::Unknown,
        "MACSEQ waiting-key test unexpectedly authenticated"))
    {
        return false;
    }

    if (!Check(result,
        verify_result.reason == AuthReason::WaitingForKey,
        "MACSEQ waiting-key test did not return WaitingForKey"))
    {
        return false;
    }

    return true;
}

void OsnmaSelfTest::Fail(Result& result,
    const char* message)
{
    result.passed = false;
    ++result.failed_count;

    if (result.first_failure[0] == '\0' && message != nullptr)
    {
#if defined(_MSC_VER)
        strncpy_s(result.first_failure.data(),
            result.first_failure.size(),
            message,
            _TRUNCATE);
#else
        std::strncpy(result.first_failure.data(),
            message,
            result.first_failure.size() - 1);

        result.first_failure[result.first_failure.size() - 1] = '\0';
#endif
    }
}

bool OsnmaSelfTest::Check(Result& result,
    bool condition,
    const char* message)
{
    if (condition)
        return true;

    Fail(result, message);
    return false;
}
