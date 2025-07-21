#include "../../inc/cssl.hpp"
#include "../common/jsonParser.hpp"
#include "utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <ostream>
#include <string>
#include <vector>

using namespace cssl::Parser;

cssl::DIGEST_MODE sha_name(const std::string& s) {
    static const std::unordered_map<std::string, cssl::DIGEST_MODE> sha_map = {
        {"HMACSHA1", cssl::DIGEST_MODE::SHA_1},
        {"HMACSHA224", cssl::DIGEST_MODE::SHA_224},
        {"HMACSHA256", cssl::DIGEST_MODE::SHA_256},
        {"HMACSHA384", cssl::DIGEST_MODE::SHA_384},
        {"HMACSHA512", cssl::DIGEST_MODE::SHA_512},
        {"HMACSHA3-224", cssl::DIGEST_MODE::SHA_3_224},
        {"HMACSHA3-256", cssl::DIGEST_MODE::SHA_3_256},
        {"HMACSHA3-384", cssl::DIGEST_MODE::SHA_3_384},
        {"HMACSHA3-512", cssl::DIGEST_MODE::SHA_3_512},
    };
    
    auto it = sha_map.find(s);
    return it != sha_map.end() ? it->second : cssl::DIGEST_MODE::NONE;
}

// Returns 1 on success
uint8_t runTestCase(const TestVector &vector, const TestGroup &group, const TestCase &test)
{
    uint8_t retCode = 0;
    cssl::DIGEST_MODE mode = sha_name(vector.algorithm);
    ByteArray msg = hex_to_bytes(test.params.at("msg").get<std::string>());
    ByteArray key = hex_to_bytes(test.params.at("key").get<std::string>());
    ByteArray tag = hex_to_bytes(test.params.at("tag").get<std::string>());
    std::string result = test.params.at("result").get<std::string>();

    bool expectedPass = false;

    ByteArray digestOutput = cssl::Hasher::hmac(msg, key, mode);
    //Truncate
    digestOutput.resize(tag.size());

    bool passed = (std::memcmp(digestOutput.data(), tag.data(), digestOutput.size()) == 0);
    if (result == "valid" || result == "acceptable")
        expectedPass = true;

    if(passed == expectedPass)
        retCode =  CSSL_TEST_PASSED;
    else
        retCode = CSSL_TEST_FAILED;
    return  retCode;
}

int main(int argc, char **argv)
{
    printf("\n\n\n\n");
    PRINT("BEGINNING HMAC");
    int retCode = 0;
    std::string path = "./vectors/"; // Current directory, change as needed
    return startTests(path, ".json", runTestCase);
}
