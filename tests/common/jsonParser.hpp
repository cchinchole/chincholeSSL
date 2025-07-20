#include "../../inc/utils/json.hpp"
#include "../../inc/utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>

using json = nlohmann::json;
using ParamMap = std::map<std::string, nlohmann::json>;

#define CSSL_TEST_PASSED 0
#define CSSL_TEST_SKIPPED 1
#define CSSL_TEST_FAILED 255

namespace CSSL
{
namespace Parser
{

struct TestCase
{
    int tcID;
    ParamMap params; // dynamic parameters
};

struct TestGroup
{
    ParamMap params; // dynamic group-level parameters
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
        for (auto it = group.begin(); it != group.end(); it++)
        {
            if (it.key() != "test")
            {
                tg.params[it.key()] = it.value();
            }
        }

        for (const auto &test : group["tests"])
        {
            TestCase tc;
            tc.tcID = test["tcId"];
            for (auto it = test.begin(); it != test.end(); it++)
            {
                if (it.key() != "tcId")
                {
                    tc.params[it.key()] = it.value();
                }
            }
            tg.testCases.push_back(tc);
        }
        tv.testGroups.push_back(tg);
    }

    return tv;
}

uint8_t getFormattingFilename(const std::vector<std::string> &fileNames)
{
    uint8_t longestLength = 0;
    for (const auto &str : fileNames)
    {
        if (str.length() > longestLength)
            longestLength = str.length();
    }
    return longestLength;
}


uint8_t runGroup(const TestVector &vector, const TestGroup &group, size_t *passed, size_t *failed, size_t *skipped, uint8_t (*runTestCase)(const TestVector &, const TestGroup &,const TestCase &))
{
    for (const auto &test : group.testCases)
    {
        switch(runTestCase(vector, group, test))
        {
            case CSSL_TEST_PASSED:
                *passed+=1;
                break;
            case CSSL_TEST_SKIPPED:
                *skipped+=1;
                break;
            default:
                *failed+=1;
                break;
        }
    }
    return 0;
}

uint8_t startTests(const std::string &path, const std::string &extension, uint8_t (*runTestCase)(const TestVector &, const TestGroup &,const TestCase &))
{
    uint8_t retCode = 0; //Defaulting to 0 so we know a value was set
    uint8_t longestLength = 0;
    size_t totalTests = 0;
    size_t totalPassed = 0;
    size_t totalFailed = 0;
    size_t totalSkipped = 0;

    namespace fs = std::filesystem;
    std::vector<std::string> fileNames;

    try
    {
        if (!fs::exists(path) || !fs::is_directory(path))
        {
            std::cerr << "Wrong directory";
            return 1;
        }

        for (const auto &entry : fs::directory_iterator(path))
        {
            if (entry.path().extension() == extension)
            {
                fileNames.push_back(entry.path().filename().string());
            }
        }

        longestLength = getFormattingFilename(fileNames);

        for (const auto &file : fileNames)
        {
            size_t passed = 0;
            size_t failed = 0;
            size_t skipped = 0;
            TestVector tv = parseJson(path + file);
            totalTests += tv.numberOfTests;
            for (const auto &group : tv.testGroups)
            {
                runGroup(tv, group, &passed, &failed, &skipped, runTestCase);
            }
            totalPassed += passed;
            totalFailed += failed;
            PRINT("[ \e[34m{:<{}}\e[0m ]: Passed: {:>3} Failed: {:>3}", file,
                  longestLength, passed, failed);
        }
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    if(totalFailed > 0)
        retCode = CSSL_TEST_FAILED;
    else
        retCode = CSSL_TEST_PASSED;

    if (retCode == CSSL_TEST_PASSED)
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
} // namespace Parser
} // namespace cSSL
