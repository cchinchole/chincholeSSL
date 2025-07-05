#include "../inc/crypto/ec.hpp"
#include "../inc/utils/logger.hpp"
#include "hash/sha.hpp"
#include "utils/bytes.hpp"
#include <openssl/bn.h>
#include <print>
#include <stdio.h>

int main()
{
    cECKey key(ECGroup::P256);
    cECKey key2(ECGroup::P256);
    cECSignature sig;
    cECSignature sig2;

    DIGEST_MODE hashMode = DIGEST_MODE::SHA_512;
    ByteArray msg = hexToBytes("aabbccddeeffaabbcceeddeedd11001100");

    EC_Generate_KeyPair(key);

    if (EC_GenerateSignature(key, sig, msg, hashMode) != 0)
        printf("Failed to generate signature\n");

    std::println("Testing Point {}", *key.getGroup()->G);

    EC_Generate_KeyPair(key2);

    if (EC_GenerateSignature(key2, sig2, msg, hashMode) != 0)
        printf("Failed to generate signature\n");

    printf("Verifying against correct signature: %s\n",
           EC_VerifySignature(key, sig, msg, hashMode) == 0 ? "Passed!"
                                                            : "Failed!");
    printf("Verifying against wrong signature: %s\n",
           EC_VerifySignature(key, sig2, msg, hashMode) == -1 ? "Passed!"
                                                              : "Failed!");

    printf("Verifying against wrong key: %s\n",
           EC_VerifySignature(key2, sig, msg, hashMode) == -1 ? "Passed!"
                                                              : "Failed!");

    std::vector<uint8_t> foobar = hexToBytes("11aa00bb00ee11cc");
    printf("Verifying against wrong message: %s\n",
           EC_VerifySignature(key, sig, foobar, hashMode) == -1 ? "Passed!"
                                                                : "Failed!");

    return 0;
}
