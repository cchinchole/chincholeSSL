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

// Returns 1 on success
int runTestCase(const TestCase &test)
{

    bool passed = false;
    bool expectedPass = false;
    std::vector<std::string> flags = test.params.at("flags").get<std::vector<std::string>>();
    std::string value = test.params.at("value").get<std::string>();
    std::string result = test.params.at("result").get<std::string>();

    if (std::find(flags.begin(), flags.end(), "NegativeOfPrime") != flags.end())
    {
        return 2;
    }

    BIGNUM *check = hexToBignum(value);
    passed = checkIfPrime(check);
    BN_free(check);
    if (result == "valid" || result == "acceptable")
        expectedPass = true;

    if (passed != expectedPass)
        PRINT("{} Recieved {} Expected {}", test.tcID, passed, expectedPass);

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
                int skipped = 0;
                for (const auto &group : tv.testGroups)
                {
                    for (const auto &test : group.testCases)
                    {
                        int r = runTestCase(test);
                        switch(r)
                        {
                            case 0:
                                retCode = -1;
                                failed++;
                                break;
                            case 1:
                                passed++;
                                break;
                            case 2:
                                skipped++;
                                PRINT("[ {} ]: Skipped negative of a prime", test.tcID);
                                break;
                            default:
                                break;
                        }
                    }
                }
                totalpassed += passed;
                totalfailed += failed;
                PRINT("Passed {} Failed {} Skipped {}", passed, failed, skipped);
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
