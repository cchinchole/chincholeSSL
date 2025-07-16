#include "../../inc/math/primes.hpp"
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
    std::string value;
    std::string result;
    std::vector<std::string> flags;
};

struct TestGroup
{
    std::string type;
    std::vector<TestCase> testCases;
};

struct TestVector
{
    std::string algorithm;
    int numberOfTests;
    std::vector<std::string> header;
    std::map<std::string, std::string> notes;
    std::string schema;
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
    tv.numberOfTests = j["numberOfTests"];
    tv.header = j["header"].get<std::vector<std::string>>();
    tv.notes = j["notes"].get<std::map<std::string, std::string>>();
    tv.schema = j["schema"];

    for (const auto &group : j["testGroups"])
    {
        TestGroup tg;
        tg.type = group["type"];

        for (const auto &test : group["tests"])
        {
            TestCase tc;
            tc.tcID = test["tcId"];
            tc.comment = test["comment"];
            tc.value = test["value"];
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

// Returns 1 on success
int runTestCase(const TestCase &test)
{

    bool passed = false;
    bool expectedPass = false;

    if (std::find(test.flags.begin(), test.flags.end(), "NegativeOfPrime") !=
        test.flags.end())
    {
        return 2;
    }

    BIGNUM *check = hexToBignum(test.value);
    passed = checkIfPrime(check);
    BN_free(check);
    if (test.result == "valid" || test.result == "acceptable")
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
