// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

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

bool OsnmaMacLookupTable::IsTargetConsistent(const OsnmaMacLookupSlot& expected,
    int32_t prna,
    int32_t prnd)
{
    if (!expected.valid)
        return false;

    if (prna <= 0 || prna > 255)
        return false;

    if (prnd <= 0 || prnd > 255)
        return false;

    if (expected.target == OsnmaMacTagAuthTarget::Flexible)
        return true;

    if (expected.target == OsnmaMacTagAuthTarget::Self)
        return prnd == prna;

    if (expected.target == OsnmaMacTagAuthTarget::External)
        return prnd != prna;

    return false;
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

int32_t OsnmaMacLookupTable::MessageIndexFromGst(const GnssTime& gst,
    int32_t msg_count)
{
    if (!IsTimeValid(gst))
        return -1;

    if (msg_count <= 0)
        return -1;

    const int32_t half_minute =
        static_cast<int32_t>(gst.tow / 30.0);

    if (half_minute < 0)
        return -1;

    return half_minute % msg_count;
}

bool OsnmaMacLookupTable::GetExpectedSlot(int32_t maclt,
    const GnssTime& gst,
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

    const int32_t message_index =
        MessageIndexFromGst(gst, entry.msg_count);

    if (message_index < 0)
        return false;

    out = entry.slots[message_index][tag_index];

    return out.valid;
}

bool OsnmaMacLookupTable::IsTagConsistent(int32_t maclt,
    const GnssTime& gst,
    int32_t prna,
    const OsnmaMackTagInfo& tag)
{
    OsnmaMacLookupSlot expected{};

    if (!GetExpectedSlot(maclt, gst, tag.index, expected))
        return false;

    if (IsFlexible(expected))
    {
        return tag.adkd != OsnmaAdkd::Reserved &&
            IsTargetConsistent(expected, prna, tag.prnd);
    }

    return SameAdkd(expected.adkd, tag.adkd) &&
        IsTargetConsistent(expected, prna, tag.prnd);
}

int32_t OsnmaMacLookupTable::GetNominalDelaySubframes(
    int32_t maclt,
    const GnssTime& gst,
    const OsnmaMackTagInfo& tag)
{
    OsnmaMacLookupSlot expected{};

    if (!GetExpectedSlot(maclt, gst, tag.index, expected))
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
