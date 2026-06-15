#include "osnma_self_test.h"

#include <cstring>
#include <vector>

#include "galileo_nav_candidate.h"
#include "osnma_crypto.h"
#include "osnma_mac_input.h"
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
        kroot.mac_lookup_table = 33;

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

    return result;
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

    /*
        Tag0 / ADKD0:
            8 + 8 + 32 + 8 + 2 + 549 = 607 bits
            padded to 608 bits = 76 bytes
    */
    if (!Check(result,
        msg.size() == 76,
        "Tag0 ADKD0 message size is not 76 bytes"))
    {
        return false;
    }

    if (!Check(result,
        CheckHeader(msg, 7, 7, 1, 2),
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

    /*
        Tag-Info entry index 3 should use CTR = index + 1 = 4.
    */
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

    /*
        Tag-Info entry index 1 should use CTR = index + 1 = 2.
    */
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

    /*
        ADKD4:
            8 + 8 + 32 + 8 + 2 + 141 = 199 bits
            padded to 200 bits = 25 bytes
    */
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
