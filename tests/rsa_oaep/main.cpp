#include "../../inc/crypto/rsa.hpp"
#include "../../inc/utils/bytes.hpp"
#include "../../inc/utils/logger.hpp"
#include "../common/jsonParser.hpp"
#include <openssl/bn.h>
#include <string>

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
uint8_t runTestCase(const TestVector &vector, const TestGroup &group, const TestCase &test)
{
    uint8_t retCode = 0;
    bool expectedPass = false;
    size_t keySize = group.params.at("keysize").get<size_t>();
    std::string result = test.params.at("result").get<std::string>();
    std::string groupD = group.params.at("d").get<std::string>();
    std::string groupE = group.params.at("e").get<std::string>();
    std::string groupN = group.params.at("n").get<std::string>();
    DIGEST_MODE mgfSha = sha_name(group.params.at("mgfSha").get<std::string>());
    DIGEST_MODE groupSha = sha_name(group.params.at("sha").get<std::string>());
    ByteArray label = hexToBytes(test.params.at("label").get<std::string>());
    ByteArray msg = hexToBytes(test.params.at("msg").get<std::string>());
    ByteArray ct = hexToBytes(test.params.at("ct").get<std::string>());
    ByteArray decrypted;
    cSSL::RSA rsa(keySize);

    rsa.loadPrivateKey(groupN, groupD);
    rsa.loadPublicKey(groupN, groupE);
    rsa.addOAEP(label, groupSha, mgfSha);

    if (result == "valid" || result == "acceptable")
    {
        expectedPass = true;
    }

    decrypted = rsa.decrypt(ct);

    bool passed = (std::equal(decrypted.begin(), decrypted.end(), msg.begin(), msg.end()));

    if(passed == expectedPass)
        retCode = CSSL_TEST_PASSED;

    return retCode;
}

int main()
{
    printf("\n\n\n\n");
    PRINT("BEGINNING RSA OAEP SIGNATURE");
    std::string path = "./vectors/";
    std::string extension = ".json";

    uint8_t retCode = startTests(path, extension, runTestCase);

    return retCode;
}
