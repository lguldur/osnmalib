// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "osnma_dsm_content.h"
#include "osnma_types.h"

class OsnmaKrootVerifier
{
public:
    bool Verify(const OsnmaDsmKroot& kroot,
                const OsnmaDsmPkr& public_key,
                AuthReason& reason_out) const;
};
