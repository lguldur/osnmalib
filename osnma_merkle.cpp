// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include "osnma_merkle.h"
#include "osnma_crypto.h"

#include <cstring>

void OsnmaMerkleVerifier::Reset()
{
    has_root_ = false;
    root_ = {};
}

bool OsnmaMerkleVerifier::SetRoot(const std::uint8_t* root_32_bytes)
{
    if (root_32_bytes == nullptr)
        return false;

    for (int32_t i = 0; i < NODE_BYTES; ++i)
        root_[i] = root_32_bytes[i];

    has_root_ = true;
    return true;
}

bool OsnmaMerkleVerifier::HasRoot() const
{
    return has_root_;
}

bool OsnmaMerkleVerifier::HashLeaf(const OsnmaDsmPkr& pkr,
                                   std::array<std::uint8_t, NODE_BYTES>& out,
                                   AuthReason& reason_out) const
{
    if (pkr.public_key_size_bytes < 0 ||
        pkr.public_key_size_bytes > OsnmaDsmPkr::MAX_PUBLIC_KEY_BYTES)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    // Leaf = (NPKT || NPKID) + public key
    std::array<std::uint8_t, 1 + OsnmaDsmPkr::MAX_PUBLIC_KEY_BYTES> leaf{};

    leaf[0] = static_cast<std::uint8_t>(
        ((static_cast<int32_t>(pkr.new_public_key_type) & 0x0F) << 4) |
        (pkr.new_public_key_id & 0x0F));

    for (int32_t i = 0; i < pkr.public_key_size_bytes; ++i)
        leaf[1 + i] = pkr.public_key[i];

    const int32_t size = 1 + pkr.public_key_size_bytes;

    if (!OsnmaSha256(leaf.data(), size, out.data()))
    {
        reason_out = AuthReason::InternalError;
        return false;
    }

    return true;
}

bool OsnmaMerkleVerifier::HashNode(const std::array<std::uint8_t, NODE_BYTES>& left,
                                   const std::array<std::uint8_t, NODE_BYTES>& right,
                                   std::array<std::uint8_t, NODE_BYTES>& out,
                                   AuthReason& reason_out) const
{
    std::array<std::uint8_t, 2 * NODE_BYTES> concat{};

    for (int32_t i = 0; i < NODE_BYTES; ++i)
        concat[i] = left[i];

    for (int32_t i = 0; i < NODE_BYTES; ++i)
        concat[NODE_BYTES + i] = right[i];

    if (!OsnmaSha256(concat.data(),
                     static_cast<int32_t>(concat.size()),
                     out.data()))
    {
        reason_out = AuthReason::InternalError;
        return false;
    }

    return true;
}

bool OsnmaMerkleVerifier::VerifyPkr(const OsnmaDsmPkr& pkr,
                                    AuthReason& reason_out) const
{
    if (!has_root_)
    {
        reason_out = AuthReason::WaitingForKey;
        return false;
    }

    if (!pkr.valid_layout)
    {
        reason_out = AuthReason::InvalidFrameFormat;
        return false;
    }

    if (pkr.new_public_key_type != OsnmaNewPublicKeyType::EcdsaP256Sha256 &&
        pkr.new_public_key_type != OsnmaNewPublicKeyType::EcdsaP521Sha512)
    {
        reason_out = AuthReason::UnsupportedMessage;
        return false;
    }

    std::array<std::uint8_t, NODE_BYTES> node{};

    if (!HashLeaf(pkr, node, reason_out))
        return false;

    int32_t id = pkr.message_id;

    for (int32_t level = 0; level < TREE_DEPTH; ++level)
    {
        std::array<std::uint8_t, NODE_BYTES> next{};

        const bool node_is_left = ((id & 1) == 0);

        if (node_is_left)
        {
            if (!HashNode(node,
                          pkr.intermediate_tree_nodes[level],
                          next,
                          reason_out))
                return false;
        }
        else
        {
            if (!HashNode(pkr.intermediate_tree_nodes[level],
                          node,
                          next,
                          reason_out))
                return false;
        }

        node = next;
        id >>= 1;
    }

    if (std::memcmp(node.data(), root_.data(), NODE_BYTES) != 0)
    {
        reason_out = AuthReason::MerkleVerificationFailed;
        return false;
    }

    reason_out = AuthReason::None;
    return true;
}
