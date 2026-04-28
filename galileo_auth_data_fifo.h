#pragma once

#include <cstdint>
#include <list>

#include "GALDataStructures.h"

class AuthEphRecord
{
public:
    AuthEphRecord();

    GALEphDecodedType data{};
};

class AuthIonoRecord
{
public:
    AuthIonoRecord();

    GALIonoDecodedType data{};
};

class AuthTimeRecord
{
public:
    AuthTimeRecord();

    GALTimeDecodedType data{};
};

class GalileoAuthDataFifo
{
public:
    void Reset();

    void PushEph(const GALEphDecodedType& eph);
    void PushIono(const GALIonoDecodedType& iono);
    void PushTime(const GALTimeDecodedType& time);

    bool PopEph(GALEphDecodedType& eph);
    bool PopIono(GALIonoDecodedType& iono);
    bool PopTime(GALTimeDecodedType& time);

    int32_t EphCount() const;
    int32_t IonoCount() const;
    int32_t TimeCount() const;

private:
    std::list<AuthEphRecord> eph_;
    std::list<AuthIonoRecord> iono_;
    std::list<AuthTimeRecord> time_;
};
