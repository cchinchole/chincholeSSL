#include "../../inc/utils/json.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>

using json = nlohmann::json;
using ParamMap = std::map<std::string, nlohmann::json>;

namespace cSSL
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
} // namespace Parser
} // namespace cSSL
