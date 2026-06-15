#pragma once

#include <array>
#include <cstdint>

#include "osnma_mack.h"
#include "osnma_types.h"

enum class OsnmaMacTagAuthTarget
{
    Unknown = 0,
    Self,
    External,
    Flexible
};

struct OsnmaMacLookupSlot
{
    bool valid = false;

    OsnmaAdkd adkd = OsnmaAdkd::Reserved;
    OsnmaMacTagAuthTarget target = OsnmaMacTagAuthTarget::Unknown;
};

class OsnmaMacLookupTable
{
public:
    static constexpr int32_t MAX_MESSAGES = 2;
    static constexpr int32_t MAX_TAGS = 10;

public:
    static bool GetExpectedSlot(int32_t maclt,
        int32_t macseq,
        int32_t tag_index,
        OsnmaMacLookupSlot& out);

    static bool IsTagConsistent(int32_t maclt,
        int32_t macseq,
        const OsnmaMackTagInfo& tag);

    static int32_t GetNominalDelaySubframes(int32_t maclt,
        int32_t macseq,
        const OsnmaMackTagInfo& tag);

private:
    struct Entry
    {
        int32_t id = -1;
        int32_t msg_count = 0;
        int32_t tag_count = 0;

        std::array<std::array<OsnmaMacLookupSlot, MAX_TAGS>, MAX_MESSAGES> slots{};
    };

private:
    static bool FindEntry(int32_t maclt, Entry& out);

    static OsnmaMacLookupSlot Slot00S();
    static OsnmaMacLookupSlot Slot00E();
    static OsnmaMacLookupSlot Slot04S();
    static OsnmaMacLookupSlot Slot12S();
    static OsnmaMacLookupSlot Slot12E();
    static OsnmaMacLookupSlot SlotFLX();

    static bool IsFlexible(const OsnmaMacLookupSlot& slot);

    static bool SameAdkd(OsnmaAdkd a, OsnmaAdkd b);
};
