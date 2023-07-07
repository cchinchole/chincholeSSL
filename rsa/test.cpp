#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <chrono>
#include <vector>
#include <iostream>
#include <fstream>
#include "inc/test.hpp"
#include <math.h>
#include "inc/json.hpp"

void readParameters()
{
    std::ifstream f("test.json");
    nlohmann::json data = nlohmann::json::parse(f);
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new();

    auto &students = data["test-data"];
    for(auto &testData : students)
    {
        //std::cout << testData << std::endl;
        std::cout << "name: " << testData["name"].get<std::string>() << std::endl;
        BN_set_word(p, testData["age"].get<std::int64_t>());
        printf("\n%s\n", BN_bn2dec(p));
    }
}

void testFunction()
{
    nlohmann::json j;
    j["pi"] = 3.14159;
    j["happy"] = true;
    j["list"] = {1,2,3};
    std::ofstream o("test.json");
    o << j << std::endl;
}



