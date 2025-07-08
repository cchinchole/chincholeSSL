#include "../../inc/crypto/aes.hpp"
#include "../../inc/hash/sha.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

struct SiggenTest
{
    std::string COUNT; // "Msg" or "MD"
    std::string KEY;
    std::string IV;
    std::string CIPHERTEXT;
    std::string PLAINTEXT;
};

struct CurveHashTests
{
    std::string state;
    std::vector<SiggenTest> tests;
};

struct SiggenRsp
{
    std::vector<CurveHashTests> curve_hash_tests;
};

static std::string trim(const std::string &s)
{
    auto a = s.find_first_not_of(" \t\r\n");
    auto b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos ? "" : s.substr(a, b - a + 1));
}

SiggenRsp parseSigGen(const std::string &filename)
{
    SiggenRsp rsp;
    CurveHashTests current_ch;
    SiggenTest current_test;
    std::ifstream in(filename);
    std::string line;

    while (std::getline(in, line))
    {
        line = trim(line);
        if (line.empty() || line.front() == '#')
            continue;

        auto brack = line.find('[');
        if (brack != std::string::npos)
        {
            auto endbracket = line.find(']');
            if (endbracket != std::string::npos)
            {
                std::string hsh =
                    trim(line.substr(brack + 1, endbracket - brack - 1));
                // If there are any tests in the current test group, save it
                if (!current_test.COUNT.empty())
                {
                    current_ch.tests.push_back(current_test);
                    current_test = SiggenTest{};
                }
                // If the current curve-hash pair has tests, save it
                if (!current_ch.tests.empty())
                {
                    rsp.curve_hash_tests.push_back(current_ch);
                    current_ch = CurveHashTests{};
                }
                current_ch.state = hsh;
            }
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (key == "COUNT")
        {
            if (!current_test.COUNT.empty())
            {
                current_ch.tests.push_back(current_test);
                current_test = SiggenTest();
            }
            current_test.COUNT = val;
        }
        else if (key == "KEY")
            current_test.KEY = val;
        else if (key == "IV")
            current_test.IV = val;
        else if (key == "CIPHERTEXT")
            current_test.CIPHERTEXT = val;
        else if (key == "PLAINTEXT")
            current_test.PLAINTEXT = val;
    }

    // Save the last test if it exists
    if (!current_test.COUNT.empty())
    {
        current_ch.tests.push_back(current_test);
    }
    // Save the last curve-hash pair if it has tests
    if (!current_ch.tests.empty())
    {
        rsp.curve_hash_tests.push_back(current_ch);
    }

    return rsp;
}

AES_MODE getMode(std::string &s)
{
    static const std::unordered_map<std::string, AES_MODE> stringToEnum = {
        {"ECB", AES_MODE::ECB}, {"CBC", AES_MODE::CBC}, {"CTR", AES_MODE::CTR},
        {"CFB", AES_MODE::CFB}, {"OFB", AES_MODE::OFB},
    };

    auto it = stringToEnum.find(s);
    if (it == stringToEnum.end())
        return AES_MODE::NONE;

    return it->second;
}

AES_KEYSIZE getKeySize(std::string &s)
{
    static const std::unordered_map<std::string, AES_KEYSIZE> stringToEnum = {
        {"128", AES_KEYSIZE::m128},
        {"192", AES_KEYSIZE::m192},
        {"256", AES_KEYSIZE::m256},
    };

    auto it = stringToEnum.find(s);
    return it->second;
}

void runTest(std::string path, std::string fileName, std::string sMode,
             std::string keySize, int *passed, int *failed)
{

    AES_MODE mode = getMode(sMode);
    AES_KEYSIZE kSize = getKeySize(keySize);
    if (mode == AES_MODE::NONE)
    {
        printf("Invalid AES mode\n");
        return;
    }
    auto rsp = parseSigGen(path + fileName);
    int pe = 0, fe = 0;
    int pd = 0, fd = 0;
    for (const auto &ch : rsp.curve_hash_tests)
    {
        for (const auto &t : ch.tests)
        {
            if (ch.state == "ENCRYPT")
            {
                AES_CTX ctx(mode, kSize);

                // ctx->mode = mode
                AES_KeyExpansion(ctx, hexToBytes(t.KEY));

                if (ctx.mode != AES_MODE::ECB)
                    AES_SetIV(ctx, hexToBytes(t.IV));

                std::vector<uint8_t> buffer = hexToBytes(t.PLAINTEXT);
                std::vector<uint8_t> output = AES_Encrypt(ctx, buffer);
                std::string hexOutput = bytesToHex(output);
                if (std::memcmp(output.data(), hexToBytes(t.CIPHERTEXT).data(),
                                output.size()) == 0)
                    pe++;
                else
                    fe++;
            }
            else if (ch.state == "DECRYPT")
            {
                AES_CTX ctx(mode, kSize);

                AES_KeyExpansion(ctx, hexToBytes(t.KEY));
                if (ctx.mode != AES_MODE::ECB)
                    AES_SetIV(ctx, hexToBytes(t.IV));

                std::vector<uint8_t> buffer = hexToBytes(t.CIPHERTEXT);
                std::vector<uint8_t> output = AES_Decrypt(ctx, buffer);

                if (std::memcmp(output.data(), hexToBytes(t.PLAINTEXT).data(),
                                output.size()) == 0)
                    pd++;
                else
                    fd++;
            }
        }
    }
    std::cout << "Result [ " << fileName << " ]: " << std::endl
              << "Enc: " << pe << " passed " << fe << " failed." << std::endl
              << "Dec: " << pd << " passed " << fd << " failed." << std::endl
              << std::endl;
    *passed += (pe + pd);
    *failed += (fe + fd);
}

int main()
{

    int ret = 0;
    int tests_performed = 0;
    int passed = 0;
    int failed = 0;
    int test_files = 0;
    namespace fs = std::filesystem;
    std::string path = "./vectors/";
    try
    {

        if (!fs::exists(path) || !fs::is_directory(path))
        {
            std::cerr << "Wrong directory";
            return 1;
        }

        std::regex key_size_regex("(128|192|256)\\.rsp$");
        for (const auto &entry : fs::directory_iterator(path))
        {
            if (entry.path().extension() == ".rsp")
            {
                std::string fileName = entry.path().filename().string();

                std::string cipher = fileName.substr(0, 3);
                std::string key_size = "Not found";

                std::smatch match;
                if (std::regex_search(fileName, match, key_size_regex))
                {
                    key_size = match[1].str();
                }

                std::cout << "AES Mode: " << std::string(cipher + key_size)
                          << " " << fileName << std::endl;

                runTest(path, fileName, cipher, key_size, &passed, &failed);
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

    OPENSSL_cleanup();
    return ret;
}
