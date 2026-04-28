#include "galileo_auth_data_fifo.h"

AuthEphRecord::AuthEphRecord()
{
    data = GALEphDecodedType{};

    data.messageid = GAL_EPHEM_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVN = static_cast<unsigned long>(0x80000000u);
    data.Source = static_cast<unsigned long>(0x80000000u);

    data.Toc = INT_DONOTUSE;
    data.af2 = DOUBLE_DONOTUSE;
    data.af1 = DOUBLE_DONOTUSE;
    data.af0 = DOUBLE_DONOTUSE;
    data.af0_1 = DOUBLE_DONOTUSE;

    data.WNToc = static_cast<unsigned long>(0x80000000u);
    data.WNToe = static_cast<unsigned long>(0x80000000u);
    data.IODNav = static_cast<unsigned long>(0x80000000u);

    data.Crs = DOUBLE_DONOTUSE;
    data.DeltaN = DOUBLE_DONOTUSE;
    data.M0 = DOUBLE_DONOTUSE;
    data.Cuc = DOUBLE_DONOTUSE;
    data.Ecc = DOUBLE_DONOTUSE;
    data.Cus = DOUBLE_DONOTUSE;
    data.sqrtA = DOUBLE_DONOTUSE;
    data.Toe = INT_DONOTUSE;
    data.Cic = DOUBLE_DONOTUSE;
    data.Omega0 = DOUBLE_DONOTUSE;
    data.Cis = DOUBLE_DONOTUSE;
    data.i0 = DOUBLE_DONOTUSE;
    data.Crc = DOUBLE_DONOTUSE;
    data.Omega = DOUBLE_DONOTUSE;
    data.OmegaDot = DOUBLE_DONOTUSE;
    data.IDot = DOUBLE_DONOTUSE;

    data.HealthAndSisaInBinary = false;

    data.Health_OSSOL = static_cast<unsigned long>(0x80000000u);
    data.Health_PRS = static_cast<unsigned long>(0x80000000u);
    data.SISA_L1E5a = static_cast<unsigned long>(0x80000000u);
    data.SISA_L1E5b = static_cast<unsigned long>(0x80000000u);
    data.SISA_L1AE6A = static_cast<unsigned long>(0x80000000u);

    data.DataSources = static_cast<unsigned long>(0x80000000u);
    data.SISA = static_cast<unsigned long>(0x80000000u);
    data.SVHealth = static_cast<unsigned long>(0x80000000u);

    data.BGD_L1E5a = DOUBLE_DONOTUSE;
    data.BGD_L1E5b = DOUBLE_DONOTUSE;
    data.BGD_L1AE6A = DOUBLE_DONOTUSE;

    data.CNAVEncrypt = static_cast<unsigned long>(0x80000000u);
    data.SISA_used = static_cast<unsigned long>(0x80000000u);

    data.CRC = INT_DONOTUSE;
}

AuthIonoRecord::AuthIonoRecord()
{
    data = GALIonoDecodedType{};

    data.messageid = GAL_IONO_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVID = static_cast<unsigned char>(0);
    data.Source = static_cast<unsigned char>(0);

    data.ai0 = DOUBLE_DONOTUSE;
    data.ai1 = DOUBLE_DONOTUSE;
    data.ai2 = DOUBLE_DONOTUSE;

    data.StormFlags = static_cast<unsigned char>(0);
}

AuthTimeRecord::AuthTimeRecord()
{
    data = GALTimeDecodedType{};

    data.messageid = GAL_TIME_TYPE;
    data.MessageTime = DOUBLE_DONOTUSE;
    data.MessageWeek = INT_DONOTUSE;

    data.SVID = static_cast<unsigned char>(0);
    data.Source = static_cast<unsigned char>(0);

    data.a0 = DOUBLE_DONOTUSE;
    data.a1 = DOUBLE_DONOTUSE;

    data.T0_UTC = static_cast<int>(0x80000000u);
    data.WN0_UTC = static_cast<int>(0x80000000u);
    data.WN_LSF = static_cast<int>(0x80000000u);
    data.DeltaT_LSF = static_cast<int>(0x80000000u);
    data.DeltaT_LS = static_cast<int>(0x80000000u);
    data.DN_LSF = static_cast<int>(0x80000000u);
}

void GalileoAuthDataFifo::Reset()
{
    eph_.clear();
    iono_.clear();
    time_.clear();
}

void GalileoAuthDataFifo::PushEph(const GALEphDecodedType& eph)
{
    AuthEphRecord r;
    r.data = eph;
    eph_.push_back(r);
}

void GalileoAuthDataFifo::PushIono(const GALIonoDecodedType& iono)
{
    AuthIonoRecord r;
    r.data = iono;
    iono_.push_back(r);
}

void GalileoAuthDataFifo::PushTime(const GALTimeDecodedType& time)
{
    AuthTimeRecord r;
    r.data = time;
    time_.push_back(r);
}

bool GalileoAuthDataFifo::PopEph(GALEphDecodedType& eph)
{
    if (eph_.empty())
        return false;

    eph = eph_.front().data;
    eph_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopIono(GALIonoDecodedType& iono)
{
    if (iono_.empty())
        return false;

    iono = iono_.front().data;
    iono_.pop_front();
    return true;
}

bool GalileoAuthDataFifo::PopTime(GALTimeDecodedType& time)
{
    if (time_.empty())
        return false;

    time = time_.front().data;
    time_.pop_front();
    return true;
}

int32_t GalileoAuthDataFifo::EphCount() const
{
    return static_cast<int32_t>(eph_.size());
}

int32_t GalileoAuthDataFifo::IonoCount() const
{
    return static_cast<int32_t>(iono_.size());
}

int32_t GalileoAuthDataFifo::TimeCount() const
{
    return static_cast<int32_t>(time_.size());
}
