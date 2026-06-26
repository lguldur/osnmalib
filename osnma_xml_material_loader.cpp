// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#include "osnma_xml_material_loader.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    static std::string ReadTextFile(const char* filename)
    {
        if (filename == nullptr || filename[0] == '\0')
            return {};

        std::ifstream in(filename, std::ios::binary);

        if (!in.is_open())
            return {};

        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    static std::string Trim(const std::string& in)
    {
        std::size_t first = 0;
        std::size_t last = in.size();

        while (first < last && std::isspace(static_cast<unsigned char>(in[first])) != 0)
            ++first;

        while (last > first && std::isspace(static_cast<unsigned char>(in[last - 1])) != 0)
            --last;

        return in.substr(first, last - first);
    }

    static std::string ToLower(std::string s)
    {
        for (char& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        return s;
    }

    static bool ReadTagText(const std::string& xml,
        const std::string& tag,
        std::string& out)
    {
        out.clear();

        const std::string open = "<" + tag + ">";
        const std::string close = "</" + tag + ">";

        const std::size_t p0 = xml.find(open);

        if (p0 == std::string::npos)
            return false;

        const std::size_t value_start = p0 + open.size();
        const std::size_t p1 = xml.find(close, value_start);

        if (p1 == std::string::npos)
            return false;

        out = Trim(xml.substr(value_start, p1 - value_start));
        return !out.empty();
    }

    static bool ReadTagInt(const std::string& xml,
        const std::string& tag,
        int32_t& out)
    {
        std::string text;

        if (!ReadTagText(xml, tag, text))
            return false;

        try
        {
            out = std::stoi(text);
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    static int32_t HexValue(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';

        if (c >= 'a' && c <= 'f')
            return 10 + c - 'a';

        if (c >= 'A' && c <= 'F')
            return 10 + c - 'A';

        return -1;
    }

    static bool HexToBytes(const std::string& hex_in,
        std::uint8_t* out,
        int32_t out_capacity,
        int32_t& out_size)
    {
        out_size = 0;

        std::string hex;
        hex.reserve(hex_in.size());

        for (char c : hex_in)
        {
            if (std::isspace(static_cast<unsigned char>(c)) == 0)
                hex.push_back(c);
        }

        if (hex.empty() || (hex.size() % 2) != 0)
            return false;

        const int32_t size = static_cast<int32_t>(hex.size() / 2);

        if (size > out_capacity)
            return false;

        for (int32_t i = 0; i < size; ++i)
        {
            const int32_t hi = HexValue(hex[static_cast<std::size_t>(2 * i)]);
            const int32_t lo = HexValue(hex[static_cast<std::size_t>(2 * i + 1)]);

            if (hi < 0 || lo < 0)
                return false;

            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }

        out_size = size;
        return true;
    }

    static bool HexToArray32(const std::string& hex,
        std::array<std::uint8_t, 32>& out)
    {
        int32_t size = 0;

        if (!HexToBytes(hex,
            out.data(),
            static_cast<int32_t>(out.size()),
            size))
        {
            return false;
        }

        return size == static_cast<int32_t>(out.size());
    }

    static OsnmaNewPublicKeyType PublicKeyTypeFromText(const std::string& text)
    {
        const std::string lower = ToLower(text);

        if (lower.find("p-256") != std::string::npos &&
            lower.find("sha-256") != std::string::npos)
        {
            return OsnmaNewPublicKeyType::EcdsaP256Sha256;
        }

        if (lower.find("p-521") != std::string::npos &&
            lower.find("sha-512") != std::string::npos)
        {
            return OsnmaNewPublicKeyType::EcdsaP521Sha512;
        }

        if (lower.find("alert") != std::string::npos)
            return OsnmaNewPublicKeyType::OsnmaAlertMessage;

        return OsnmaNewPublicKeyType::Unknown;
    }

    static bool FindMerkleRootNode(const std::string& xml,
        std::array<std::uint8_t, 32>& root_out)
    {
        std::size_t pos = 0;

        while (true)
        {
            const std::size_t start = xml.find("<TreeNode>", pos);

            if (start == std::string::npos)
                return false;

            const std::size_t end = xml.find("</TreeNode>", start);

            if (end == std::string::npos)
                return false;

            const std::string node = xml.substr(start, end - start);

            int32_t j = -1;
            int32_t i = -1;

            if (ReadTagInt(node, "j", j) &&
                ReadTagInt(node, "i", i) &&
                j == 4 &&
                i == 0)
            {
                std::string xji;

                if (!ReadTagText(node, "x_ji", xji))
                    return false;

                return HexToArray32(xji, root_out);
            }

            pos = end + 11;
        }
    }

    static bool ContainsPkIdInFilename(const std::filesystem::path& path,
        int32_t pkid)
    {
        const std::string name = path.filename().string();
        const std::string a = "newPKID_" + std::to_string(pkid);
        const std::string b = "PKID_" + std::to_string(pkid);

        return name.find(a) != std::string::npos ||
            name.find(b) != std::string::npos;
    }

    static bool FindFirstXmlFile(const std::filesystem::path& folder,
        const std::string& name_must_contain,
        int32_t pkid,
        std::filesystem::path& out)
    {
        out.clear();

        if (!std::filesystem::exists(folder))
            return false;

        for (const std::filesystem::directory_entry& entry :
            std::filesystem::directory_iterator(folder))
        {
            if (!entry.is_regular_file())
                continue;

            const std::filesystem::path path = entry.path();
            const std::string name = path.filename().string();

            if (path.extension() != ".xml")
                continue;

            if (name.find(name_must_contain) == std::string::npos)
                continue;

            if (pkid >= 0 && !ContainsPkIdInFilename(path, pkid))
                continue;

            out = path;
            return true;
        }

        return false;
    }

    static std::filesystem::path TestVectorsRootFromCsv(const char* csv_filename)
    {
        if (csv_filename == nullptr)
            return {};

        std::filesystem::path p(csv_filename);
        p = p.lexically_normal();

        std::filesystem::path parent = p.parent_path();

        while (!parent.empty())
        {
            if (parent.filename() == "osnma_test_vectors")
                return parent.parent_path();

            parent = parent.parent_path();
        }

        return {};
    }

    static std::string ScenarioFromCsv(const char* csv_filename)
    {
        if (csv_filename == nullptr)
            return {};

        const std::filesystem::path p(csv_filename);
        const std::filesystem::path parent = p.parent_path();

        return parent.filename().string();
    }

    static bool LoadPublicKeyByPkid(const std::filesystem::path& test_vectors_root,
        int32_t merkle_tree_id,
        int32_t pkid,
        OsnmaAuthenticator& authenticator,
        int32_t& loaded_count)
    {
        if (pkid < 0)
            return true;

        const std::filesystem::path folder =
            test_vectors_root /
            "cryptographic_material" /
            ("Merkle_tree_" + std::to_string(merkle_tree_id)) /
            "PublicKey";

        std::filesystem::path public_key_xml;

        if (!FindFirstXmlFile(folder,
            "OSNMA_PublicKey_",
            pkid,
            public_key_xml))
        {
            return false;
        }

        if (!OsnmaXmlMaterialLoader::LoadPublicKeyXmlToAuthenticator(public_key_xml.string().c_str(),
            authenticator))
        {
            return false;
        }

        ++loaded_count;
        return true;
    }
}

bool OsnmaXmlMaterialLoader::LoadMerkleTreeXml(const char* filename,
    std::array<std::uint8_t, 32>& root_out)
{
    root_out = {};

    const std::string xml = ReadTextFile(filename);

    if (xml.empty())
        return false;

    return FindMerkleRootNode(xml, root_out);
}

bool OsnmaXmlMaterialLoader::LoadPublicKeyXml(const char* filename,
    OsnmaDsmPkr& public_key_out)
{
    public_key_out = OsnmaDsmPkr{};

    const std::string xml = ReadTextFile(filename);

    if (xml.empty())
        return false;

    int32_t pkid = -1;
    int32_t length_bits = -1;
    int32_t message_id = -1;
    std::string point;
    std::string pk_type;

    if (!ReadTagInt(xml, "PKID", pkid))
        return false;

    if (!ReadTagInt(xml, "lengthInBits", length_bits))
        return false;

    if (!ReadTagText(xml, "point", point))
        return false;

    if (!ReadTagText(xml, "PKType", pk_type))
        return false;

    (void)ReadTagInt(xml, "i", message_id);

    public_key_out.number_of_blocks = 0;
    public_key_out.message_id = message_id;
    public_key_out.new_public_key_id = pkid;
    public_key_out.new_public_key_type = PublicKeyTypeFromText(pk_type);

    if (public_key_out.new_public_key_type == OsnmaNewPublicKeyType::Unknown ||
        public_key_out.new_public_key_type == OsnmaNewPublicKeyType::Reserved)
    {
        return false;
    }

    int32_t point_size = 0;

    if (!HexToBytes(point,
        public_key_out.public_key.data(),
        static_cast<int32_t>(public_key_out.public_key.size()),
        point_size))
    {
        return false;
    }

    if ((point_size * 8) != length_bits)
        return false;

    public_key_out.public_key_size_bytes = point_size;
    public_key_out.padding_size_bytes = 0;
    public_key_out.valid_layout = true;

    return true;
}

bool OsnmaXmlMaterialLoader::LoadMerkleTreeXmlToAuthenticator(const char* filename,
    OsnmaAuthenticator& authenticator)
{
    std::array<std::uint8_t, 32> root{};

    if (!LoadMerkleTreeXml(filename, root))
        return false;

    return authenticator.SetMerkleRoot(root.data());
}

bool OsnmaXmlMaterialLoader::LoadPublicKeyXmlToAuthenticator(const char* filename,
    OsnmaAuthenticator& authenticator)
{
    OsnmaDsmPkr public_key{};

    if (!LoadPublicKeyXml(filename, public_key))
        return false;

    return authenticator.AddTrustedPublicKey(public_key);
}

bool OsnmaXmlMaterialLoader::SelectionForScenario(const char* scenario_name,
    MaterialSelection& selection_out)
{
    selection_out = MaterialSelection{};

    if (scenario_name == nullptr || scenario_name[0] == '\0')
        return false;

    const std::string s = ToLower(scenario_name);

    if (s == "configuration_1")
    {
        selection_out.merkle_tree_id = 1;
        selection_out.current_pkid = 1;
        return true;
    }

    if (s == "configuration_2")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.current_pkid = 2;
        return true;
    }

    if (s == "eoc_step1" || s == "eoc_step2" ||
        s == "crev_step1" || s == "crev_step2" || s == "crev_step3" ||
        s == "npk_step1")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.current_pkid = 7;
        return true;
    }

    if (s == "npk_step2")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.current_pkid = 7;
        selection_out.new_pkid = 8;
        return true;
    }

    if (s == "npk_step3" || s == "pkrev_step1")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.current_pkid = 8;

        if (s == "pkrev_step1")
            selection_out.new_pkid = 9;

        return true;
    }

    if (s == "pkrev_step2" || s == "pkrev_step3")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.current_pkid = 9;
        return true;
    }

    if (s == "nmt_step1")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.new_merkle_tree_id = 3;
        selection_out.current_pkid = 9;
        return true;
    }

    if (s == "nmt_step2")
    {
        selection_out.merkle_tree_id = 2;
        selection_out.new_merkle_tree_id = 3;
        selection_out.current_pkid = 9;
        selection_out.new_pkid = 1;
        return true;
    }

    if (s == "nmt_step3" || s == "oam_step1" || s == "oam_step2")
    {
        selection_out.merkle_tree_id = 3;
        selection_out.current_pkid = 1;
        return true;
    }

    return false;
}

bool OsnmaXmlMaterialLoader::LoadMaterialBySelection(const char* test_vectors_root,
    const MaterialSelection& selection,
    OsnmaAuthenticator& authenticator,
    Stats* stats)
{
    if (stats != nullptr)
    {
        *stats = Stats{};
        stats->merkle_tree_id = selection.merkle_tree_id;
        stats->current_pkid = selection.current_pkid;
        stats->new_pkid = selection.new_pkid;
        stats->new_merkle_tree_id = selection.new_merkle_tree_id;
    }

    if (test_vectors_root == nullptr || test_vectors_root[0] == '\0')
        return false;

    if (selection.merkle_tree_id <= 0)
        return false;

    const std::filesystem::path root(test_vectors_root);

    const std::filesystem::path merkle_folder =
        root /
        "cryptographic_material" /
        ("Merkle_tree_" + std::to_string(selection.merkle_tree_id)) /
        "MerkleTree";

    std::filesystem::path merkle_xml;

    if (!FindFirstXmlFile(merkle_folder,
        "OSNMA_MerkleTree_",
        -1,
        merkle_xml))
    {
        return false;
    }

    if (!LoadMerkleTreeXmlToAuthenticator(merkle_xml.string().c_str(),
        authenticator))
    {
        return false;
    }

    if (stats != nullptr)
        ++stats->merkle_root_loaded;

    int32_t loaded_count = 0;

    if (!LoadPublicKeyByPkid(root,
        selection.merkle_tree_id,
        selection.current_pkid,
        authenticator,
        loaded_count))
    {
        return false;
    }

    if (selection.new_pkid >= 0)
    {
        const int32_t tree_for_new_pk =
            selection.new_merkle_tree_id > 0 ?
            selection.new_merkle_tree_id :
            selection.merkle_tree_id;

        if (!LoadPublicKeyByPkid(root,
            tree_for_new_pk,
            selection.new_pkid,
            authenticator,
            loaded_count))
        {
            return false;
        }
    }

    if (stats != nullptr)
        stats->public_keys_loaded = loaded_count;

    return true;
}

bool OsnmaXmlMaterialLoader::LoadOfficialTestVectorMaterial(const char* csv_filename,
    OsnmaAuthenticator& authenticator,
    Stats* stats)
{
    const std::filesystem::path root = TestVectorsRootFromCsv(csv_filename);
    const std::string scenario = ScenarioFromCsv(csv_filename);

    if (root.empty() || scenario.empty())
        return false;

    return LoadOfficialTestVectorMaterial(root.string().c_str(),
        scenario.c_str(),
        authenticator,
        stats);
}

bool OsnmaXmlMaterialLoader::LoadOfficialTestVectorMaterial(const char* test_vectors_root,
    const char* scenario_name,
    OsnmaAuthenticator& authenticator,
    Stats* stats)
{
    MaterialSelection selection{};

    if (!SelectionForScenario(scenario_name, selection))
        return false;

    return LoadMaterialBySelection(test_vectors_root,
        selection,
        authenticator,
        stats);
}
