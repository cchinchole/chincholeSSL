#include "../../inc/crypto/ec.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string>
#include <unordered_map>
#include <vector>

struct SiggenTest
{
    std::string msg_hex; // "Msg" or "MD"
    std::string d;
    std::string Qx;
    std::string Qy;
    std::string k;
    std::string R;
    std::string S;
};

struct CurveHashTests
{
    std::string curve;
    std::string hash;
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
            auto comma = line.find(',');
            auto endbracket = line.find(']');
            if (comma != std::string::npos && endbracket != std::string::npos)
            {
                std::string crv = trim(line.substr(1, comma - 1));
                std::string hsh =
                    trim(line.substr(comma + 1, endbracket - comma - 1));
                // If there are any tests in the current test group, save it
                if (!current_test.msg_hex.empty())
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
                current_ch.curve = crv;
                current_ch.hash = hsh;
            }
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (key == "Msg" || key == "MD")
        {
            if (!current_test.msg_hex.empty())
            {
                current_ch.tests.push_back(current_test);
                current_test = SiggenTest{};
            }
            current_test.msg_hex = val;
        }
        else if (key == "d")
        {
            current_test.d = val;
        }
        else if (key == "Qx")
        {
            current_test.Qx = val;
        }
        else if (key == "Qy")
        {
            current_test.Qy = val;
        }
        else if (key == "k")
        {
            current_test.k = val;
        }
        else if (key == "R")
        {
            current_test.R = val;
        }
        else if (key == "S")
        {
            current_test.S = val;
        }
    }

    // Save the last test if it exists
    if (!current_test.msg_hex.empty())
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

std::string hexToAscii(const std::string &hex)
{
    std::string ascii;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        ascii += byte;
    }
    return ascii;
}

int didTestSucceed(std::string s)
{
    if (s == "P")
        return 0;
    else
        return -1;
}

DIGEST_MODE haveSHA(const std::string &s)
{
    static const std::unordered_map<std::string, DIGEST_MODE> sha_map = {
        {"SHA-1", DIGEST_MODE::SHA_1},     {"SHA-224", DIGEST_MODE::SHA_224},
        {"SHA-256", DIGEST_MODE::SHA_256}, {"SHA-384", DIGEST_MODE::SHA_384},
        {"SHA-512", DIGEST_MODE::SHA_512},
    };

    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : DIGEST_MODE::NONE;
}

ECGroup haveCurve(std::string s)
{
    static const std::unordered_map<std::string, ECGroup> group_map = {
        {"P-224", ECGroup::P224},
        {"P-256", ECGroup::P256},
        {"P-384", ECGroup::P384},
        {"P-521", ECGroup::P521},
    };

    auto it = group_map.find(s);
    return it != group_map.end() ? it->second : ECGroup::NONE;
}

int main()
{
    printf("\n\n\n\n");
    PRINT("BEGINNING EC SIGGEN");
    int retCode = 0;
    auto rsp = parseSigGen("SigGen.txt");
    int totalPassed = 0, totalFailed = 0;
    for (const auto &ch : rsp.curve_hash_tests)
    {
        DIGEST_MODE shaMode = haveSHA(ch.hash);
        ECGroup group = haveCurve(ch.curve);
        int p = 0, f = 0;
        if (shaMode != DIGEST_MODE::NONE && group != ECGroup::NONE)
        {
            //std::cout << "\033[34mCurve: " << ch.curve << "\n";
            //std::cout << "Hash: " << ch.hash << "\033[0m\n";
            for (const auto &t : ch.tests)
            {
                cSSL::ECKeyPair keyPair =
                    cSSL::ECKeyPair::From(group, t.d, t.Qx, t.Qy);
                std::vector<uint8_t> msg = hexToBytes(t.msg_hex);
                cSSL::ECSignature sig = keyPair.sign(msg, shaMode);
                std::string R = sig.getPairRS().first;
                std::string S = sig.getPairRS().second;
                if (strcmp(R.c_str(), t.R.c_str()) &&
                    strcmp(S.c_str(), t.S.c_str()))
                {
                    if (keyPair.verify(sig, msg, shaMode))
                    {
                        p++;
                    }
                    else
                    {
                        f++;
                    }
                }
                else
                {
                    f++;
                }
            }
            PRINT("[ \e[34m{} {}\e[0m ]: Passed: {} Failed: {}", ch.curve, ch.hash, p, f);
        }

        if (group != ECGroup::NONE)
        {
            totalPassed += p;
            totalFailed += f;
        }
    }

    if (totalFailed > 0)
        retCode = 255;

    int totalTests = totalPassed + totalFailed;
    if (retCode == 0)
    {
        PRINT_TEST_PASS("{}/{}", totalPassed, totalTests);
    }
    else
    {
        PRINT_TEST_FAILED("{}/{} Failed: {}", totalPassed, totalTests,
                          totalFailed);
    }
    return retCode;
}
