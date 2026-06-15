#include "osnma_mac_lookup.h"

OsnmaMacLookupSlot OsnmaMacLookupTable::Slot00S()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::InavCed;
    s.target = OsnmaMacTagAuthTarget::Self;
    return s;
}

OsnmaMacLookupSlot OsnmaMacLookupTable::Slot00E()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::InavCed;
    s.target = OsnmaMacTagAuthTarget::External;
    return s;
}

OsnmaMacLookupSlot OsnmaMacLookupTable::Slot04S()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::InavTiming;
    s.target = OsnmaMacTagAuthTarget::Self;
    return s;
}

OsnmaMacLookupSlot OsnmaMacLookupTable::Slot12S()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::SlowMac;
    s.target = OsnmaMacTagAuthTarget::Self;
    return s;
}

OsnmaMacLookupSlot OsnmaMacLookupTable::Slot12E()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::SlowMac;
    s.target = OsnmaMacTagAuthTarget::External;
    return s;
}

OsnmaMacLookupSlot OsnmaMacLookupTable::SlotFLX()
{
    OsnmaMacLookupSlot s{};
    s.valid = true;
    s.adkd = OsnmaAdkd::Reserved;
    s.target = OsnmaMacTagAuthTarget::Flexible;
    return s;
}

bool OsnmaMacLookupTable::IsFlexible(const OsnmaMacLookupSlot& slot)
{
    return slot.valid &&
        slot.target == OsnmaMacTagAuthTarget::Flexible;
}

bool OsnmaMacLookupTable::SameAdkd(OsnmaAdkd a, OsnmaAdkd b)
{
    return a == b;
}

bool OsnmaMacLookupTable::FindEntry(int32_t maclt,
    Entry& out)
{
    out = Entry{};

    Entry e{};
    e.id = maclt;

    switch (maclt)
    {
    case 27:
        e.msg_count = 2;
        e.tag_count = 6;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot00E();
        e.slots[0][3] = Slot00E();
        e.slots[0][4] = Slot12S();
        e.slots[0][5] = Slot00E();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot04S();
        e.slots[1][4] = Slot12S();
        e.slots[1][5] = Slot00E();

        out = e;
        return true;

    case 28:
        e.msg_count = 2;
        e.tag_count = 10;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot00E();
        e.slots[0][3] = Slot00E();
        e.slots[0][4] = Slot00S();
        e.slots[0][5] = Slot00E();
        e.slots[0][6] = Slot00E();
        e.slots[0][7] = Slot12S();
        e.slots[0][8] = Slot00E();
        e.slots[0][9] = Slot00E();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot00S();
        e.slots[1][4] = Slot00E();
        e.slots[1][5] = Slot00E();
        e.slots[1][6] = Slot04S();
        e.slots[1][7] = Slot12S();
        e.slots[1][8] = Slot00E();
        e.slots[1][9] = Slot00E();

        out = e;
        return true;

    case 31:
        e.msg_count = 2;
        e.tag_count = 5;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot00E();
        e.slots[0][3] = Slot12S();
        e.slots[0][4] = Slot00E();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = Slot04S();

        out = e;
        return true;

    case 33:
        e.msg_count = 2;
        e.tag_count = 6;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = Slot00E();
        e.slots[0][4] = Slot12S();
        e.slots[0][5] = Slot00E();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = Slot00E();
        e.slots[1][5] = Slot12E();

        out = e;
        return true;

    case 34:
        e.msg_count = 2;
        e.tag_count = 6;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();
        e.slots[0][4] = Slot12S();
        e.slots[0][5] = Slot00E();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = Slot00E();
        e.slots[1][5] = Slot12E();

        out = e;
        return true;

    case 35:
        e.msg_count = 2;
        e.tag_count = 6;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();
        e.slots[0][4] = Slot12S();
        e.slots[0][5] = SlotFLX();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = SlotFLX();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = SlotFLX();
        e.slots[1][5] = SlotFLX();

        out = e;
        return true;

    case 36:
        e.msg_count = 2;
        e.tag_count = 5;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();
        e.slots[0][4] = Slot12S();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = Slot12E();

        out = e;
        return true;

    case 37:
        e.msg_count = 2;
        e.tag_count = 5;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = Slot00E();
        e.slots[0][4] = Slot12S();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = Slot12E();

        out = e;
        return true;

    case 38:
        e.msg_count = 2;
        e.tag_count = 5;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();
        e.slots[0][4] = Slot12S();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = SlotFLX();
        e.slots[1][3] = Slot12S();
        e.slots[1][4] = SlotFLX();

        out = e;
        return true;

    case 39:
        e.msg_count = 2;
        e.tag_count = 4;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12S();

        out = e;
        return true;

    case 40:
        e.msg_count = 2;
        e.tag_count = 4;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = Slot00E();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = Slot12S();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = Slot00E();
        e.slots[1][2] = Slot00E();
        e.slots[1][3] = Slot12E();

        out = e;
        return true;

    case 41:
        e.msg_count = 2;
        e.tag_count = 4;

        e.slots[0][0] = Slot00S();
        e.slots[0][1] = SlotFLX();
        e.slots[0][2] = Slot04S();
        e.slots[0][3] = SlotFLX();

        e.slots[1][0] = Slot00S();
        e.slots[1][1] = SlotFLX();
        e.slots[1][2] = SlotFLX();
        e.slots[1][3] = Slot12S();

        out = e;
        return true;

    default:
        return false;
    }
}

bool OsnmaMacLookupTable::GetExpectedSlot(int32_t maclt,
    int32_t macseq,
    int32_t tag_index,
    OsnmaMacLookupSlot& out)
{
    out = OsnmaMacLookupSlot{};

    Entry entry{};

    if (!FindEntry(maclt, entry))
        return false;

    if (entry.msg_count <= 0 || entry.tag_count <= 0)
        return false;

    if (tag_index < 0 || tag_index >= entry.tag_count)
        return false;

    /*
        MACSEQ selects which message sequence is used. The current code maps
        the counter cyclically over the available sequences.
    */
    const int32_t message_index =
        macseq % entry.msg_count;

    out = entry.slots[message_index][tag_index];

    return out.valid;
}

bool OsnmaMacLookupTable::IsTagConsistent(int32_t maclt,
    int32_t macseq,
    const OsnmaMackTagInfo& tag)
{
    OsnmaMacLookupSlot expected{};

    if (!GetExpectedSlot(maclt, macseq, tag.index, expected))
        return false;

    if (IsFlexible(expected))
        return tag.adkd != OsnmaAdkd::Reserved;

    return SameAdkd(expected.adkd, tag.adkd);
}

int32_t OsnmaMacLookupTable::GetNominalDelaySubframes(
    int32_t maclt,
    int32_t macseq,
    const OsnmaMackTagInfo& tag)
{
    OsnmaMacLookupSlot expected{};

    if (!GetExpectedSlot(maclt, macseq, tag.index, expected))
        return -1;

    OsnmaAdkd effective_adkd = expected.adkd;

    if (IsFlexible(expected))
        effective_adkd = tag.adkd;

    if (effective_adkd == OsnmaAdkd::InavCed)
        return 1;

    if (effective_adkd == OsnmaAdkd::InavTiming)
        return 1;

    if (effective_adkd == OsnmaAdkd::SlowMac)
        return 11;

    return -1;
}
