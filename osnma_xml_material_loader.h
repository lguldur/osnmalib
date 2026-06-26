// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>

#include "osnma_authenticator.h"
#include "osnma_dsm_content.h"

class OsnmaXmlMaterialLoader
{
public:
    struct Stats
    {
        int32_t merkle_root_loaded = 0;
        int32_t public_keys_loaded = 0;

        int32_t merkle_tree_id = -1;
        int32_t current_pkid = -1;
        int32_t new_pkid = -1;
        int32_t new_merkle_tree_id = -1;
    };

public:
    static bool LoadMerkleTreeXml(const char* filename,
        std::array<std::uint8_t, 32>& root_out);

    static bool LoadPublicKeyXml(const char* filename,
        OsnmaDsmPkr& public_key_out);

    static bool LoadMerkleTreeXmlToAuthenticator(const char* filename,
        OsnmaAuthenticator& authenticator);

    static bool LoadPublicKeyXmlToAuthenticator(const char* filename,
        OsnmaAuthenticator& authenticator);

    /*
        Load the cryptographic material associated with an official EUSPA/GSC
        OSNMA test-vector CSV. The expected directory structure is the one from
        the official Test_vectors.zip package:

            Test_vectors/
                cryptographic_material/
                osnma_test_vectors/<scenario>/<file>.csv

        The scenario -> Merkle tree / PKID mapping follows Annex B, Table 9 of
        the OSNMA Receiver Guidelines v1.3.
    */
    static bool LoadOfficialTestVectorMaterial(const char* csv_filename,
        OsnmaAuthenticator& authenticator,
        Stats* stats = nullptr);

    static bool LoadOfficialTestVectorMaterial(const char* test_vectors_root,
        const char* scenario_name,
        OsnmaAuthenticator& authenticator,
        Stats* stats = nullptr);

private:
    struct MaterialSelection
    {
        int32_t merkle_tree_id = -1;
        int32_t current_pkid = -1;
        int32_t new_pkid = -1;
        int32_t new_merkle_tree_id = -1;
    };

private:
    static bool SelectionForScenario(const char* scenario_name,
        MaterialSelection& selection_out);

    static bool LoadMaterialBySelection(const char* test_vectors_root,
        const MaterialSelection& selection,
        OsnmaAuthenticator& authenticator,
        Stats* stats);
};
