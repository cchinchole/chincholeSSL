#include "../../inc/crypto/rsa.hpp"
#include "../../inc/hash/sha.hpp"
#include "../../inc/hash/hmac.hpp"
#include "../../inc/tests/test.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/json.hpp"
#include "../../inc/utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <ostream>
#include <string>
#include <vector>

using json = nlohmann::json;

struct TestCase
{
    int tcID;
    std::string comment;
    ByteArray key;
    ByteArray msg;
    ByteArray tag;
    std::string result;
    std::vector<std::string> flags;
};

struct TestGroup
{
    int keySize;
    int tagSize;
    std::string type;
    std::vector<TestCase> testCases;
};

struct TestVector
{
    std::string algorithm;
    //std::string generatorVersion;
    int numberOfTests;
    //std::vector<std::string> header;
    //std::map<std::string, std::string> notes;
    //std::string schema;
    std::vector<TestGroup> testGroups;
};

// Parse JSON file into TestVector structure
TestVector parseJson(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        throw std::runtime_error("Unable to open JSON file");
    }

    json j;
    file >> j;

    TestVector tv;
    tv.algorithm = j["algorithm"];
    //tv.generatorVersion = j["generatorVersion"];
    tv.numberOfTests = j["numberOfTests"];
    //tv.header = j["header"].get<std::vector<std::string>>();
    //tv.notes = j["notes"].get<std::map<std::string, std::string>>();
    //tv.schema = j["schema"];

    for (const auto &group : j["testGroups"])
    {
        TestGroup tg;
        tg.keySize = group["keySize"];
        tg.tagSize = group["tagSize"];
        tg.type = group["type"];

        for (const auto &test : group["tests"])
        {
            TestCase tc;
            tc.tcID = test["tcId"];
            tc.comment = test["comment"];
            tc.key = hexToBytes(test["key"]);
            tc.msg = hexToBytes(test["msg"]);
            tc.tag = hexToBytes(test["tag"]);
            tc.result = test["result"];
            tc.flags = test["flags"].get<std::vector<std::string>>();
            tg.testCases.push_back(tc);
        }
        tv.testGroups.push_back(tg);
    }

    return tv;
}

// Convert hex string to BIGNUM
BIGNUM *hexToBignum(const std::string &hex)
{
    BIGNUM *bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

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

int runTestCase(const TestCase &test, DIGEST_MODE mode)
{

    bool passed = false;
    bool expectedPass = false;

    SHA_Context *ctx = SHA_Context_new(mode);
    uint8_t digestOutput[getSHABlockLengthByMode(mode)];
    //SHA_Update((uint8_t*)test.msg.data(), test.msg.size(), ctx);
    //SHA_Digest(digestOutput, ctx);

    hmac_sha(ctx, digestOutput, (uint8_t*)test.msg.data(), test.msg.size(), (uint8_t*)test.key.data(), test.key.size());

    if (std::memcmp(digestOutput, test.tag.data(), test.tag.size()) == 0)
        passed = true;
    if (test.result == "valid" || test.result == "acceptable")
        expectedPass = true;
    
    /*
    if (passed == expectedPass)
        PRINT("TEST {} passed.", test.tcID);
    else
    {
        PRINT("TEST {} failed.\nReturned: {} Expected: {}\n", test.tcID, passed,
              expectedPass);
    }
    */
    
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
                PRINT("Running: {}", entry.path().filename().string());
                TestVector tv =
                    parseJson(path + entry.path().filename().string());
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
                PRINT("Passed {} Failed {}\n", passed, failed);
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
