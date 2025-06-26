#include "../inc/crypto/ec.hpp"
#include "hash/sha.hpp"
#include "utils/bytes.hpp"
#include <openssl/bn.h>

int main() {
    cECKey *key = new cECKey();
    cECSignature *sig = new cECSignature();
    cECKey *key2 = new cECKey();
    cECSignature *sig2 = new cECSignature();

    SHA_MODE hashMode = SHA_MODE::SHA_512;
    std::vector<uint8_t> msg = hexToBytes("aabbccddeeffaabbcceeddeedd11001100");

    EC_Generate_KeyPair(key, ECGroup::P256);
    if(EC_GenerateSignature(key, sig, msg, hashMode) != 0)
        printf("Failed to generate signature\n");

    EC_Generate_KeyPair(key2, ECGroup::P256);

    if(EC_GenerateSignature(key2, sig2, msg, hashMode) != 0)
        printf("Failed to generate signature\n");

    /* Return code of 0 indicates signature match succeeded */
    printf("Verifying against correct signature: %s\n",
           EC_VerifySignature(key, sig, msg, hashMode) == 0 ? "Passed!" : "Failed!");
    /* Return code of -1 indicates signature match failed */
    printf("Verifying against wrong signature: %s\n",
           EC_VerifySignature(key, sig2, msg, hashMode) == -1 ? "Passed!" : "Failed!");

    /* Return code of -1 indicates signature match failed */
    printf("Verifying against wrong key: %s\n",
           EC_VerifySignature(key2, sig, msg, hashMode) == -1 ? "Passed!" : "Failed!");

    std::vector<uint8_t> foobar = hexToBytes("11aa00bb00ee11cc");
    /* Return code of -1 indicates signature match failed */
    printf("Verifying against wrong message: %s\n",
           EC_VerifySignature(key, sig, foobar, hashMode) == -1 ? "Passed!" : "Failed!");

    delete key;
    delete sig;
    delete key2;
    delete sig2;
    return 0;
}
