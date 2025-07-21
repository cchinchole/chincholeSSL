#include "../../inc/cssl.hpp"
#include "../common/jsonParser.hpp"
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <ostream>
#include <string>
#include <vector>

using namespace cssl::Parser;

// Returns 1 on success
uint8_t runTestCase(const TestVector &vector, const TestGroup &group, const TestCase &test)
{
    uint8_t retCode = CSSL_TEST_FAILED;
    bool passed = false;
    bool expectedPass = false;
    std::vector<std::string> flags = test.params.at("flags").get<std::vector<std::string>>();
    std::string value = test.params.at("value").get<std::string>();
    std::string result = test.params.at("result").get<std::string>();

    if (std::find(flags.begin(), flags.end(), "NegativeOfPrime") != flags.end())
    {
        return CSSL_TEST_SKIPPED;
    }

    BIGNUM *check = hex_to_bignum(value);
    passed = cssl::check_if_prime(check);
    BN_free(check);
    if (result == "valid" || result == "acceptable")
        expectedPass = true;

    if (passed == expectedPass)
        retCode = CSSL_TEST_PASSED;

    return retCode;
}

int main(int argc, char **argv)
{
    printf("\n\n\n\n");
    PRINT("BEGINNING PRIME VALIDITY");
    int retCode = 0;
    std::string path = "./vectors/"; // Current directory, change as needed
    retCode = startTests(path, ".json", runTestCase);
    int totalTests = 0;
    return retCode;
}
