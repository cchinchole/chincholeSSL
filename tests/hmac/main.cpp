#include "../../inc/cssl.hpp"
#include "../common/jsonParser.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <ostream>
#include <string>
#include <vector>

using namespace cSSL::Parser;

DIGEST_MODE sha_name(const std::string& s) {
    static const std::unordered_map<std::string, DIGEST_MODE> sha_map = {
        {"HMACSHA1", DIGEST_MODE::SHA_1},
        {"HMACSHA224", DIGEST_MODE::SHA_224},
        {"HMACSHA256", DIGEST_MODE::SHA_256},
        {"HMACSHA384", DIGEST_MODE::SHA_384},
        {"HMACSHA512", DIGEST_MODE::SHA_512},
        {"HMACSHA3-224", DIGEST_MODE::SHA_3_224},
        {"HMACSHA3-256", DIGEST_MODE::SHA_3_256},
        {"HMACSHA3-384", DIGEST_MODE::SHA_3_384},
        {"HMACSHA3-512", DIGEST_MODE::SHA_3_512},
    };
    
    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : DIGEST_MODE::NONE;
}

// Returns 1 on success
int test_hmac(ByteArray msg, ByteArray key, ByteArray KAT, DIGEST_MODE digestMode)
{
    ByteArray digestOutput = Hasher::hmac(msg, key, digestMode);
    //Truncate
    digestOutput.resize(KAT.size());
    return (std::memcmp(digestOutput.data(), KAT.data(), digestOutput.size()) == 0) ? 1 : 0;
}

// Returns 1 on success
int runTestCase(const TestCase &test, DIGEST_MODE mode)
{
    ByteArray msg = hexToBytes(test.params.at("msg").get<std::string>());
    ByteArray key = hexToBytes(test.params.at("key").get<std::string>());
    ByteArray tag = hexToBytes(test.params.at("tag").get<std::string>());
    std::string result = test.params.at("result").get<std::string>();

    bool passed = false;
    bool expectedPass = false;
    passed = test_hmac(msg, key, tag, mode);
    if (result == "valid" || result == "acceptable")
        expectedPass = true;

    return (passed == expectedPass);
}

int main(int argc, char **argv)
{
    int totalTests = 0;
    int retCode = 0;
    int totalpassed = 0;
    int totalfailed = 0;
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
            if (entry.path().extension() == ".json")
            {
                TestVector tv = parseJson(path + entry.path().filename().string());
                totalTests += tv.numberOfTests;
                int passed = 0;
                int failed = 0;
                for (const auto &group : tv.testGroups)
                {
                    for(const auto &test : group.testCases)
                    {
                        if (!runTestCase(test, sha_name(tv.algorithm)))
                        {
                            retCode = -1;
                            failed++;
                        }
                        else
                        {
                            passed++;
                        }
                    }
                }
                totalpassed += passed;
                totalfailed += failed;
                PRINT("[ {} ]: {} passed {} failed.", entry.path().filename().string(), passed, failed);
            }
        }
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    if(totalfailed > 0)
        retCode = 255;

    printf("Total tests: %d\nTests Succeeded: %d\nTests failed: %d\n", totalTests,
          totalpassed, totalfailed);

    if(retCode == 0)
        printf("\e[0;32mSUCCEEDED\e[0;37m\n");
    else
        printf("\e[0;31mFAILED\e[0;37m\n");
    return retCode;
}
