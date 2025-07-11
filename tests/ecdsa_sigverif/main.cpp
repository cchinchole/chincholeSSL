#include "../../inc/crypto/ec.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <string>
#include <vector>

struct SiggenTest
{
    std::string msg_hex; // "Msg" or "MD"
    std::string Qx;
    std::string Qy;
    std::string R;
    std::string S;
    std::string Result;
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
        else if (key == "Qx")
        {
            current_test.Qx = val;
        }
        else if (key == "Qy")
        {
            current_test.Qy = val;
        }
        else if (key == "R")
        {
            current_test.R = val;
        }
        else if (key == "S")
        {
            current_test.S = val;
        }
        else if (key == "Result")
        {
            if (val.front() == 'F')
                current_test.Result = 'F';
            else
                current_test.Result = 'P';
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

int didTestSucceed(std::string s)
{
    if (s == "P")
        return 0;
    else
        return -1;
}

DIGEST_MODE haveSHA(const std::string& s) {
    static const std::unordered_map<std::string, DIGEST_MODE> sha_map = {
        {"SHA-1", DIGEST_MODE::SHA_1},
        {"SHA-224", DIGEST_MODE::SHA_224},
        {"SHA-256", DIGEST_MODE::SHA_256},
        {"SHA-384", DIGEST_MODE::SHA_384},
        {"SHA-512", DIGEST_MODE::SHA_512},
        {"SHA3_224", DIGEST_MODE::SHA_3_224},
        {"SHA3_256", DIGEST_MODE::SHA_3_256},
        {"SHA3_384", DIGEST_MODE::SHA_3_384},
        {"SHA3_512", DIGEST_MODE::SHA_3_512}
    };
    
    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : DIGEST_MODE::NONE;
}

ECGroup haveCurve(std::string s) {
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
    int ret = 0;
    auto rsp = parseSigGen("SigVer.rsp");
    int passed = 0, failed = 0;
    for (const auto &ch : rsp.curve_hash_tests)
    {
        DIGEST_MODE shaMode = haveSHA(ch.hash);
        ECGroup group = haveCurve(ch.curve);

        if (shaMode != DIGEST_MODE::NONE && group != ECGroup::NONE)
        {
            std::cout << "\033[34mCurve: " << ch.curve << "\n";
            std::cout << "Hash: " << ch.hash << "\033[0m\n";
            int p = 0, f = 0;
            for (const auto &t : ch.tests)
            {
                /*
                 std::cout << "Msg: " << t.msg_hex << "\n";
                 std::cout << "Qx = (" << t.Qx << ")\n";
                 std::cout << "Qy = (" << t.Qy << ")\n";
                 std::cout << "Signature (R) = (" << t.R << ")\n";
                 std::cout << "Signature (S) = (" << t.S << ")\n";
                 std::cout << "Expected Result =(" << t.Result << ")\n";
               */

                cECKey key(group);
                BN_hex2bn(&key.pub.x, t.Qx.c_str());
                BN_hex2bn(&key.pub.y, t.Qy.c_str());

                cECSignature sig;
                BN_hex2bn(&sig.R, t.R.c_str());
                BN_hex2bn(&sig.S, t.S.c_str());

                std::vector<uint8_t> msgBytes = hexToBytes(t.msg_hex);
                if (EC_VerifySignature(key, sig, msgBytes, shaMode) ==
                    didTestSucceed(t.Result))
                {
                    // printf("\033[1;32m Test Succeeded!\n");
                    p++;
                    // std::cout << "\033[0m";
                }
                else
                {
                    f++;
                    // printf("\033[31m Test Failed!\n");
                    // std::cout << "\033[0m";
                }

                // printf("\n\n");

                // Clean up allocated memory
            }
            std::cout << "Results: " << p << " passed " << f << " failed."
                      << std::endl
                      << std::endl;
            passed += p;
            failed += f;
        }
    }
    std::cout << "Passed: " << passed << std::endl
              << "Failed: " << failed << std::endl;
    if (failed > 0)
        ret = -1;
    if (ret == 0)
        PRINT("\e[0;32mSUCCEEDED\e[0;37m");
    else
        PRINT("\e[0;31mFAILED\e[0;37m");

    return ret;
}
