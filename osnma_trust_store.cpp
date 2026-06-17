#include "osnma_trust_store.h"

#include <cstdio>

void OsnmaTrustStore::Reset()
{
    for (auto& p : pkr_list_)
        p = PkrEntry{};

    for (auto& k : kroot_list_)
        k = KrootEntry{};

    merkle_.Reset();
}

bool OsnmaTrustStore::SetMerkleRoot(const std::uint8_t* root_32_bytes)
{
    return merkle_.SetRoot(root_32_bytes);
}

int32_t OsnmaTrustStore::FindFreePkrSlot() const
{
    for (int32_t i = 0; i < MAX_PKR; ++i)
    {
        if (!pkr_list_[i].valid)
            return i;
    }

    return 0;
}

int32_t OsnmaTrustStore::FindFreeKrootSlot() const
{
    for (int32_t i = 0; i < MAX_KROOT; ++i)
    {
        if (!kroot_list_[i].valid)
            return i;
    }

    return 0;
}


bool OsnmaTrustStore::AddTrustedPublicKey(const OsnmaDsmPkr& public_key,
    const GnssTime& time)
{
    if (!public_key.valid_layout ||
        public_key.new_public_key_id < 0 ||
        public_key.public_key_size_bytes <= 0)
    {
        return false;
    }

    const int32_t idx = FindFreePkrSlot();

    pkr_list_[idx].valid = true;
    pkr_list_[idx].merkle_verified = true;
    pkr_list_[idx].time = time;
    pkr_list_[idx].pkr = public_key;

    printf("Trusted PublicKey loaded: npkid=%d npkt=%d pk_bytes=%d pk_first=%02X\n",
        public_key.new_public_key_id,
        static_cast<int32_t>(public_key.new_public_key_type),
        public_key.public_key_size_bytes,
        public_key.public_key_size_bytes > 0 ? public_key.public_key[0] : 0);

    return true;
}

bool OsnmaTrustStore::AddPkr(const OsnmaDsmPkr& pkr,
                             const GnssTime& time)
{
    const int32_t idx = FindFreePkrSlot();

    AuthReason reason = AuthReason::None;
    const bool verified = merkle_.VerifyPkr(pkr, reason);

    pkr_list_[idx].valid = true;
    pkr_list_[idx].merkle_verified = verified;
    pkr_list_[idx].time = time;
    pkr_list_[idx].pkr = pkr;

    return verified;
}

bool OsnmaTrustStore::AddKroot(const OsnmaDsmKroot& kroot,
    const GnssTime& time)
{
    const int32_t idx = FindFreeKrootSlot();

    bool verified = false;

    const int32_t public_key_idx = FindVerifiedPkrById(kroot.public_key_id);
    const OsnmaDsmPkr* public_key =
        public_key_idx >= 0 ? &pkr_list_[public_key_idx].pkr : nullptr;

    printf("AddKroot: kroot_pkid=%d trusted_public_key=%d",
        kroot.public_key_id,
        public_key != nullptr ? 1 : 0);

    if (public_key != nullptr)
    {
        printf(" npkid=%d npkt=%d pk_bytes=%d pk_first=%02X",
            public_key->new_public_key_id,
            static_cast<int32_t>(public_key->new_public_key_type),
            public_key->public_key_size_bytes,
            public_key->public_key_size_bytes > 0 ? public_key->public_key[0] : 0);
    }

    printf("\n");

    if (public_key != nullptr)
    {
        AuthReason reason = AuthReason::None;
        verified = kroot_verifier_.Verify(kroot, *public_key, reason);

        printf("AddKroot result: kroot_pkid=%d verified=%d reason=%d\n",
            kroot.public_key_id,
            verified ? 1 : 0,
            static_cast<int32_t>(reason));
    }

    kroot_list_[idx].valid = true;
    kroot_list_[idx].signature_verified = verified;
    kroot_list_[idx].time = time;
    kroot_list_[idx].kroot = kroot;

    return verified;
}

int32_t OsnmaTrustStore::FindLatestVerifiedPkr() const
{
    int32_t best = -1;

    for (int32_t i = 0; i < MAX_PKR; ++i)
    {
        if (!pkr_list_[i].valid || !pkr_list_[i].merkle_verified)
            continue;

        if (best < 0 ||
            DiffSeconds(pkr_list_[i].time, pkr_list_[best].time) > 0.0)
        {
            best = i;
        }
    }

    return best;
}


int32_t OsnmaTrustStore::FindVerifiedPkrById(int32_t public_key_id) const
{
    int32_t best = -1;

    for (int32_t i = 0; i < MAX_PKR; ++i)
    {
        if (!pkr_list_[i].valid || !pkr_list_[i].merkle_verified)
            continue;

        if (pkr_list_[i].pkr.new_public_key_id != public_key_id)
            continue;

        if (best < 0 ||
            DiffSeconds(pkr_list_[i].time, pkr_list_[best].time) > 0.0)
        {
            best = i;
        }
    }

    return best;
}

int32_t OsnmaTrustStore::FindLatestVerifiedKroot() const
{
    int32_t best = -1;

    for (int32_t i = 0; i < MAX_KROOT; ++i)
    {
        if (!kroot_list_[i].valid || !kroot_list_[i].signature_verified)
            continue;

        if (best < 0 ||
            DiffSeconds(kroot_list_[i].time, kroot_list_[best].time) > 0.0)
        {
            best = i;
        }
    }

    return best;
}

bool OsnmaTrustStore::HasTrustedPublicKey() const
{
    return FindLatestVerifiedPkr() >= 0;
}

bool OsnmaTrustStore::HasTrustedKroot() const
{
    return FindLatestVerifiedKroot() >= 0;
}

const OsnmaDsmPkr* OsnmaTrustStore::GetTrustedPublicKey() const
{
    const int32_t idx = FindLatestVerifiedPkr();

    if (idx < 0)
        return nullptr;

    return &pkr_list_[idx].pkr;
}

const OsnmaDsmKroot* OsnmaTrustStore::GetTrustedKroot() const
{
    const int32_t idx = FindLatestVerifiedKroot();

    if (idx < 0)
        return nullptr;

    return &kroot_list_[idx].kroot;
}
