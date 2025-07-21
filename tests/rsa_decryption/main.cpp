#include "../../inc/cssl.hpp"
#include "../common/jsonParser.hpp"
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <print>
#include <string>
#include <vector>

struct RSATest
{
    int id = -1;
    std::string n;
    std::string e;
    std::string d;
    std::string c;
    std::string k;
    std::string result;
};

struct ModuloGroupTests
{
    int modulo;
    std::vector<RSATest> tests;
};

struct RSADecryptionRsp
{
    std::vector<ModuloGroupTests> curve_hash_tests;
};

static std::string trim(const std::string &s)
{
    auto a = s.find_first_not_of(" \t\r\n");
    auto b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos ? "" : s.substr(a, b - a + 1));
}

RSADecryptionRsp parseSigGen(const std::string &filename)
{
    RSADecryptionRsp rsp;
    ModuloGroupTests current_ch;
    RSATest current_test;
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
            auto equals = line.find('=');
            if (endbracket != std::string::npos && equals != std::string::npos)
            {
                std::string modulo =
                    trim(line.substr(equals + 1, endbracket - equals - 1));

                // Save the current test if it has data (e.g., n is non-empty)
                if (!current_test.n.empty())
                {
                    current_ch.tests.push_back(current_test);
                    current_test = RSATest{};
                }
                // Save the current modulo group if it has tests
                if (!current_ch.tests.empty())
                {
                    rsp.curve_hash_tests.push_back(current_ch);
                    current_ch = ModuloGroupTests{};
                }
                try
                {
                    current_ch.modulo = std::stoi(modulo);
                }
                catch (const std::exception &e)
                {
                    PRINT("Error parsing modulo: {}", e.what());
                    continue;
                }
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
            // Save the current test if it has data (e.g., n is non-empty)
            if (!current_test.n.empty())
            {
                current_ch.tests.push_back(current_test);
                current_test = RSATest{};
            }
            try
            {
                current_test.id = std::stoi(val);
            }
            catch (const std::exception &e)
            {
                PRINT("Error parsing COUNT: {}", e.what());
                current_test.id = -1; // Keep going with invalid ID
            }
        }
        else if (key == "n")
        {
            current_test.n = val;
        }
        else if (key == "e")
        {
            current_test.e = val;
        }
        else if (key == "d")
        {
            current_test.d = val;
        }
        else if (key == "c")
        {
            current_test.c = val;
        }
        else if (key == "Result")
        {
            current_test.result = val;
        }
        else if (key == "k")
        {
            current_test.k = val;
        }
    }

    // Save the last test if it has data
    if (!current_test.n.empty())
    {
        current_ch.tests.push_back(current_test);
    }
    // Save the last modulo group if it has tests
    if (!current_ch.tests.empty())
    {
        rsp.curve_hash_tests.push_back(current_ch);
    }

    in.close();
    return rsp;
}

int main()
{
    printf("\n\n\n\n");
    PRINT("BEGINNING RSA DECRYPTION");
    int retCode = 0;
    auto rsp = parseSigGen("vectors/RSADPComponent800_56B.txt");
    int totalPassed = 0, totalFailed = 0, totalTests = 0, totalSkipped = 0;
    for (const auto &ch : rsp.curve_hash_tests)
    {
        int p = 0, f = 0;
        int kBits = ch.modulo;
        for (const auto &t : ch.tests)
        {
            totalTests++;
            cssl::Rsa rsa(kBits);
            if (t.n.empty() || t.d.empty())
            {
                totalSkipped++;
                continue;
            }
            rsa.load_private_key(t.n, t.d);
            auto k = rsa.decrypt(hex_to_bytes(t.c));
            bool expectedRes = t.result == "Pass" ? true : false;
            bool res = !k.empty();
            if (expectedRes)
            {
                auto expectedK = hex_to_bytes(t.k);
                if (memcmp(expectedK.data(), k.data(), expectedK.size()) == 0)
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
                res == false ? p++ : f++;
            }
        }
        totalPassed += p;
        totalFailed += f;
        PRINT("[ \e[34mKeySize: {}\e[0m ]: Passed: {} Failed: {}", ch.modulo, p,
              f);
    }

    if (totalFailed > 0)
        retCode = 255;

    if (retCode == 0)
    {
        PRINT_TEST_PASS("{}/{} {}", totalPassed, totalTests,
                        totalSkipped != 0
                            ? std::format("\e[33m{} skipped\e[0m", totalSkipped)
                            : "");
    }
    else
    {
        PRINT_TEST_FAILED(
            "{}/{} Failed: {} {}", totalPassed, totalTests, totalFailed,
            totalSkipped != 0 ? std::format("{} skipped", totalSkipped) : "");
    }
    return retCode;
}
