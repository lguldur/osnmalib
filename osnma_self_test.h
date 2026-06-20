#pragma once

#include <array>
#include <cstdint>

class OsnmaSelfTest
{
public:
    struct Result
    {
        bool passed = true;

        int32_t test_count = 0;
        int32_t failed_count = 0;

        std::array<char, 256> first_failure{};
    };

public:
    static Result RunAll();

private:
    static bool TestTag0Adkd0LengthAndHeader(Result& result);
    static bool TestTagInfoAdkd0LengthAndCtr(Result& result);
    static bool TestTagInfoAdkd4LengthAndCtr(Result& result);
    static bool TestMissingCedDataFails(Result& result);
    static bool TestMissingTimingDataFails(Result& result);
    static bool TestTeslaSha256OneStepAcceptsValidKey(Result& result);
    static bool TestTeslaSha256OneStepRejectsWrongKey(Result& result);
    static bool TestMacseqValidThenMissingNavData(Result& result);
    static bool TestMacseqRejectsWrongMacseq(Result& result);
    static bool TestMacseqWaitsForFutureKey(Result& result);
    static bool TestAuthenticatedCedDecode(Result& result);
    static bool TestAuthenticatedTimingDecode(Result& result);
    static bool TestPegasusRowMapping(Result& result);
    static bool TestCedCompletionEpochPreserved(Result& result);
    static bool TestAllZeroOsnmaSubframeIsNormal(Result& result);
    static bool TestAllZeroMackWithNonZeroHkrootIsRejected(Result& result);

    static void Fail(Result& result,
        const char* message);

    static bool Check(Result& result,
        bool condition,
        const char* message);
};