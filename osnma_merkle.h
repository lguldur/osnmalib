#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "osnma_dsm_content.h"
#include "osnma_types.h"

class OsnmaMerkleVerifier
{
public:
    static constexpr int32_t NODE_BYTES = 32;
    static constexpr int32_t TREE_DEPTH = 4;

public:
    void Reset();

    bool SetRoot(const std::uint8_t* root_32_bytes);
    bool HasRoot() const;

    bool VerifyPkr(const OsnmaDsmPkr& pkr,
                   AuthReason& reason_out) const;

private:
    bool HashLeaf(const OsnmaDsmPkr& pkr,
                  std::array<std::uint8_t, NODE_BYTES>& out,
                  AuthReason& reason_out) const;

    bool HashNode(const std::array<std::uint8_t, NODE_BYTES>& left,
                  const std::array<std::uint8_t, NODE_BYTES>& right,
                  std::array<std::uint8_t, NODE_BYTES>& out,
                  AuthReason& reason_out) const;

private:
    bool has_root_ = false;
    std::array<std::uint8_t, NODE_BYTES> root_{};
};
