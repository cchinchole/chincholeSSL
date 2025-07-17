#include "../../inc/crypto/rsa.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/json.hpp"
#include "../../inc/utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>
#include <openssl/bn.h>
#include <string>
#include <variant>
#include <vector>
#include "../common/jsonParser.hpp"

using namespace cSSL::Parser;


DIGEST_MODE sha_name(const std::string &s)
{
    static const std::unordered_map<std::string, DIGEST_MODE> sha_map = {
        {"SHA-1", DIGEST_MODE::SHA_1},
        {"SHA-224", DIGEST_MODE::SHA_224},
        {"SHA-256", DIGEST_MODE::SHA_256},
        {"SHA-384", DIGEST_MODE::SHA_384},
        {"SHA-512", DIGEST_MODE::SHA_512}};

    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : DIGEST_MODE::NONE;
}

// Returns 1 on success
int runTestCase(cSSL::RSA &key, const DIGEST_MODE sha, const DIGEST_MODE mgfSha,
                const TestCase &test)
{

    bool passed = false;
    bool expectedPass = false;
    ByteArray label = hexToBytes(test.params.at("label").get<std::string>());
    ByteArray msg = hexToBytes(test.params.at("msg").get<std::string>());
    ByteArray ct = hexToBytes(test.params.at("ct").get<std::string>());
    std::string result = test.params.at("result").get<std::string>();
    key.addOAEP(label, sha, mgfSha);
    ByteArray decrypted = key.decrypt(ct);

    passed = (std::equal(decrypted.begin(), decrypted.end(), msg.begin(),
                         msg.end()));

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
                PRINT("Running: {}", entry.path().filename().string());
                TestVector tv =
                    parseJson(path + entry.path().filename().string());
                totalTests += tv.numberOfTests;
                int passed = 0;
                int failed = 0;
                for (const auto &group : tv.testGroups)
                {
                    int keySize = group.params.at("keysize").get<int>();
                    std::string groupD =
                        group.params.at("d").get<std::string>();
                    std::string groupE =
                        group.params.at("e").get<std::string>();
                    std::string groupN =
                        group.params.at("n").get<std::string>();
                    DIGEST_MODE mgfSha =
                        sha_name(group.params.at("mgfSha").get<std::string>());
                    DIGEST_MODE groupSha =
                        sha_name(group.params.at("sha").get<std::string>());

                    cSSL::RSA rsa(keySize);
                    rsa.loadPrivateKey(groupN, groupD);
                    rsa.loadPublicKey(groupN, groupE);
                    for (const auto &test : group.testCases)
                    {
                        if (runTestCase(rsa, groupSha, mgfSha, test))
                        {
                            passed++;
                        }
                        else
                        {
                            retCode = -1;
                            failed++;
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

    if (totalfailed > 0)
        retCode = 255;

    printf("Total tests: %d\nTests Succeeded: %d\nTests failed: %d\n",
           totalTests, totalpassed, totalfailed);

    if (retCode == 0)
        printf("\e[0;32mSUCCEEDED\e[0;37m\n");
    else
        printf("\e[0;31mFAILED\e[0;37m\n");
    return retCode;
}
