#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include "../../inc/crypto/rsa.hpp"
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
                std::string modulo = trim(line.substr(equals + 1, endbracket - equals - 1));

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
    int ret = 0;
    auto rsp = parseSigGen("vectors/RSADPComponent800_56B.txt");
    int passed = 0, failed = 0, ranTest = 0, totalTest = 0;
    for (const auto &ch : rsp.curve_hash_tests)
    {
        int p = 0, f = 0;
        int kBits = ch.modulo;
        for (const auto &t : ch.tests)
        {
            totalTest++;
            cSSL::RSA rsa(kBits);
            if(t.n.empty() || t.d.empty())
            {
                PRINT("Either N or D empty, skipping test.");
                continue;
            }
            rsa.loadPrivateKey(t.n, t.d);
            auto k = rsa.decrypt(hexToBytes(t.c));
            bool expectedRes = t.result == "Pass" ? true : false;
            bool res = !k.empty();
            ranTest++;
            if(expectedRes)
            {
                auto expectedK = hexToBytes(t.k);
                if(memcmp(expectedK.data(), k.data(), expectedK.size()) == 0)
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
        passed += p;
        failed += f;
    }
    std::cout << "Passed: " << passed << std::endl
              << "Failed: " << failed << std::endl;
    if (failed > 0)
        ret = -1;
    if (ret == 0)
        PRINT("\e[0;32mSUCCEEDED\e[0;37m");
    else
        PRINT("\e[0;31mFAILED\e[0;37m");
    PRINT("Ran: {}/{}", ranTest, totalTest);

    return ret;
}
