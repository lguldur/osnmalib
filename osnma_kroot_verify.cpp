#include "osnma_kroot_verify.h"
#include "osnma_crypto.h"

#include <array>
#include <cstdio>

static void PrintHexPrefix(const char* name,
    const std::uint8_t* data,
    int32_t size,
    int32_t max_count)
{
    printf("%s", name);

    if (data == nullptr || size <= 0)
    {
        printf("<empty>\n");
        return;
    }

    const int32_t count = (size < max_count) ? size : max_count;

    for (int32_t i = 0; i < count; ++i)
        printf("%02X", data[i]);

    if (size > count)
        printf("...");

    printf("\n");
}

bool OsnmaKrootVerifier::Verify(const OsnmaDsmKroot& kroot,
    const OsnmaDsmPkr& public_key,
    AuthReason& reason_out) const
{
    printf("KROOT verify input: "
        "nma=%02X kroot_pkid=%d npkid=%d npkt=%d "
        "raw_size=%d sig_offset=%d sig_size=%d "
        "pk_size=%d pk_first=%02X ecdsa=%d\n",
        kroot.nma_header,
        kroot.public_key_id,
        public_key.new_public_key_id,
        static_cast<int32_t>(public_key.new_public_key_type),
        kroot.raw_size_bytes,
        kroot.signature_offset_bytes,
        kroot.signature_size_bytes,
        public_key.public_key_size_bytes,
        public_key.public_key_size_bytes > 0 ? public_key.public_key[0] : 0,
        static_cast<int32_t>(kroot.ecdsa_function));

    if (!kroot.valid_layout || !public_key.valid_layout)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (kroot.raw_size_bytes <= 0 ||
        kroot.signature_offset_bytes <= 0 ||
        kroot.signature_size_bytes <= 0)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if ((kroot.signature_offset_bytes + kroot.signature_size_bytes) >
        kroot.raw_size_bytes)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (public_key.public_key_size_bytes <= 0)
    {
        reason_out = AuthReason::PublicKeyVerificationFailed;
        return false;
    }

    /*
        OSNMA SIS ICD v1.1, Eq. 14:

            M = NMA Header || CIDKR || Reserved1 || HF || MF || KS || TS ||
                MACLT || Reserved2 || WNK || TOWHK || alpha || KROOT

        kroot.raw starts with:

            NBDK || PKID || CIDKR || ...

        Therefore the signed message is NOT kroot.raw[0..signature_offset).
        We must replace the first DSM-KROOT byte, NBDK||PKID, with the NMA header,
        and keep the rest starting at CIDKR.
    */

    std::array<std::uint8_t, OsnmaDsmKroot::MAX_RAW_BYTES> signed_message{};

    const int32_t signed_message_size = kroot.signature_offset_bytes;

    if (signed_message_size <= 0 ||
        signed_message_size > static_cast<int32_t>(signed_message.size()))
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    signed_message[0] = kroot.nma_header;

    for (int32_t i = 1; i < signed_message_size; ++i)
        signed_message[i] = kroot.raw[i];

    const std::uint8_t* signature = kroot.signature.data();
    const int32_t signature_size = kroot.signature_size_bytes;

    printf("KROOT verify sizes: signed_message_size=%d signature_size=%d\n",
        signed_message_size,
        signature_size);

    PrintHexPrefix("KROOT public key: ",
        public_key.public_key.data(),
        public_key.public_key_size_bytes,
        40);

    PrintHexPrefix("KROOT signed message prefix: ",
        signed_message.data(),
        signed_message_size,
        24);

    if (signed_message_size > 24)
    {
        const int32_t tail_offset = signed_message_size - 24;

        PrintHexPrefix("KROOT signed message suffix: ",
            signed_message.data() + tail_offset,
            24,
            24);
    }

    PrintHexPrefix("KROOT signature prefix: ",
        signature,
        signature_size,
        24);

    if (public_key.new_public_key_type ==
        OsnmaNewPublicKeyType::EcdsaP256Sha256)
    {
        if (!OsnmaEcdsaVerifyP256Sha256(public_key.public_key.data(),
            public_key.public_key_size_bytes,
            signed_message.data(),
            signed_message_size,
            signature,
            signature_size))
        {
            reason_out = AuthReason::SignatureVerificationFailed;
            return false;
        }
    }
    else if (public_key.new_public_key_type ==
        OsnmaNewPublicKeyType::EcdsaP521Sha512)
    {
        if (!OsnmaEcdsaVerifyP521Sha512(public_key.public_key.data(),
            public_key.public_key_size_bytes,
            signed_message.data(),
            signed_message_size,
            signature,
            signature_size))
        {
            reason_out = AuthReason::SignatureVerificationFailed;
            return false;
        }
    }
    else
    {
        reason_out = AuthReason::UnsupportedMessage;
        return false;
    }

    reason_out = AuthReason::None;
    return true;
}
