#include "osnma_kroot_verify.h"
#include "osnma_crypto.h"

bool OsnmaKrootVerifier::Verify(const OsnmaDsmKroot& kroot,
                                const OsnmaDsmPkr& public_key,
                                AuthReason& reason_out) const
{
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

    const std::uint8_t* message = kroot.raw.data();
    const int32_t message_size = kroot.signature_offset_bytes;

    const std::uint8_t* signature = kroot.signature.data();
    const int32_t signature_size = kroot.signature_size_bytes;

    if (public_key.new_public_key_type ==
        OsnmaNewPublicKeyType::EcdsaP256Sha256)
    {
        if (!OsnmaEcdsaVerifyP256Sha256(public_key.public_key.data(),
                                        public_key.public_key_size_bytes,
                                        message,
                                        message_size,
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
                                        message,
                                        message_size,
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
