#pragma once

#include <array>
#include <cstdint>

#include "gnss_time.h"
#include "osnma_dsm_content.h"
#include "osnma_kroot_verify.h"
#include "osnma_merkle.h"

class OsnmaTrustStore
{
public:
    static constexpr int32_t MAX_PRN = 256;

public:
    void Reset();

    bool SetMerkleRoot(const std::uint8_t* root_32_bytes);

    /*
        Add a Public Key that has already been trusted externally, for example
        after loading it from the GSC/official XML material and validating the
        surrounding PKI/certificate chain outside this class.
    */
    bool AddTrustedPublicKey(const OsnmaDsmPkr& public_key,
        const GnssTime& time);

    bool AddPkr(const OsnmaDsmPkr& pkr,
                const GnssTime& time);

    bool AddKroot(const OsnmaDsmKroot& kroot,
                  const GnssTime& time);

    bool HasTrustedPublicKey() const;
    bool HasTrustedKroot() const;

    const OsnmaDsmPkr* GetTrustedPublicKey() const;
    const OsnmaDsmKroot* GetTrustedKroot() const;

private:
    struct PkrEntry
    {
        bool valid = false;
        bool merkle_verified = false;

        GnssTime time{};
        OsnmaDsmPkr pkr{};
    };

    struct KrootEntry
    {
        bool valid = false;
        bool signature_verified = false;

        GnssTime time{};
        OsnmaDsmKroot kroot{};
    };

private:
    static constexpr int32_t MAX_PKR = 8;
    static constexpr int32_t MAX_KROOT = 8;

    std::array<PkrEntry, MAX_PKR> pkr_list_{};
    std::array<KrootEntry, MAX_KROOT> kroot_list_{};

    OsnmaMerkleVerifier merkle_{};
    OsnmaKrootVerifier kroot_verifier_{};

private:
    int32_t FindFreePkrSlot() const;
    int32_t FindFreeKrootSlot() const;

    int32_t FindLatestVerifiedPkr() const;
    int32_t FindVerifiedPkrById(int32_t public_key_id) const;
    int32_t FindLatestVerifiedKroot() const;
};
