#include "../../inc/hash/sha.hpp"
#include "../../inc/tests/test.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <ostream>
#include <string>
#include <vector>
#include <unordered_map>


#ifndef TEST_SHA_LOG
#define TEST_SHA_LOG 0
#endif

struct SHATest
{
    std::string MD;  /* Digest expected in hex */
    std::string Len; /* Msg len in hex (bytes) */
    std::string Msg; /* Msg in hex */
};

struct SHARsp
{
    std::vector<SHATest> tests;
};

static std::string trim(const std::string &s)
{
    auto a = s.find_first_not_of(" \t\r\n");
    auto b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos ? "" : s.substr(a, b - a + 1));
}

SHARsp parseFile(const std::string &filename)
{
    SHARsp rsp;
    SHATest current;
    std::ifstream in(filename);
    std::string line;

    while (std::getline(in, line))
    {
        line = trim(line);
        if (line.empty() || line.front() == '#')
            continue;

        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key == "Len")
        {
            if (!current.Len.empty())
            {
                rsp.tests.push_back(current);
                current = SHATest();
            }
            current.Len = val;
        }
        else if (key == "Msg")
            current.Msg = val;
        else if (key == "MD")
            current.MD = val;
    }
    if (!current.MD.empty())
        rsp.tests.push_back(current);
    return rsp;
}

void runTest(std::string path, std::string fileName, DIGEST_MODE shaMode,
             int *passed, int *failed)
{
    auto rsp = parseFile(path + fileName);
    int p = 0, f = 0;
    for (const auto &t : rsp.tests)
    {
#if TEST_SHA_LOG
        std::cout << "Len: " << t.Len << "\n";
        std::cout << "Msg = (" << t.Msg << ")\n";
        std::cout << "MD = (" << t.MD << ")\n";
#endif
        if (testSHA((char *)hexToBytes(t.Msg).data(), std::stoi(t.Len) / 8,
                    (char *)t.MD.c_str(), shaMode) == 0)
            p++;
        else
            f++;
    }
    *passed += p;
    *failed += f;
    std::cout << "Results [ " << fileName << " ]" << p << " passed " << " f "
              << f << std::endl
              << std::endl;
}

DIGEST_MODE haveSHA(const std::string& s) {
    static const std::unordered_map<std::string, DIGEST_MODE> sha_map = {
        {"SHA1", DIGEST_MODE::SHA_1},
        {"SHA224", DIGEST_MODE::SHA_224},
        {"SHA256", DIGEST_MODE::SHA_256},
        {"SHA384", DIGEST_MODE::SHA_384},
        {"SHA512", DIGEST_MODE::SHA_512},
        {"SHA3_224", DIGEST_MODE::SHA_3_224},
        {"SHA3_256", DIGEST_MODE::SHA_3_256},
        {"SHA3_384", DIGEST_MODE::SHA_3_384},
        {"SHA3_512", DIGEST_MODE::SHA_3_512}
    };
    
    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : DIGEST_MODE::NONE;
}


int main()
{
    int ret = 0;
    int tests_performed = 0;
    int passed = 0;
    int failed = 0;
    int test_files = 0;
    namespace fs = std::filesystem;
    std::string path = "./vectors/"; // Current directory, change as needed

    try
    {

        if (!fs::exists(path) || !fs::is_directory(path))
        {
            std::cerr << "Wrong directory";
            return 1;
        }

        for (const auto &entry : fs::directory_iterator(path))
        {
            if (entry.path().extension() == ".rsp")
            {
                std::string fileName = entry.path().filename().string();
                size_t pos = fileName.find("Short");
                if (pos == std::string::npos)
                    pos = fileName.find("Long");
                if (pos == std::string::npos)
                    continue; /* Invalid file */

                std::string sha_type = fileName.substr(0, pos);
                runTest(path, fileName, haveSHA(sha_type), &passed, &failed);
                tests_performed++;
            }
        }
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    std::cout << "Results: " << passed << " passed " << failed << " failed."
              << std::endl;
    if (failed > 0)
        ret = -1;
    if (ret == 0)
        PRINT("\e[0;32mSUCCEEDED\e[0;37m");
    else
        PRINT("\e[0;31mFAILED\e[0;37m");

    return ret;
}
