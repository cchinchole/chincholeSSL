#include "../inc/crypto/rsa.hpp"
#include "../inc/utils/bytes.hpp"
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>

int main() {
    cRSAKey *key = new cRSAKey();

    /* Generate a key */
    /* Paramaters: key, public encryption exponent, bits, auxillary prime mode (Leave this true for now) */
    RSA_GenerateKey(key);

    std::string str = "Hello World";
    std::vector<uint8_t> cipher;
    cipher = RSA_Encrypt(key, charToVector(str.c_str(), str.size()));
    std::vector<uint8_t> decrypt = RSA_Decrypt(key, cipher, NULL);
    printf("Output size: %d\n", decrypt.size());
    int strresult =
        !((std::equal(decrypt.begin(), decrypt.end(), str.begin(), str.end())));
    std::cout << "- - - - - - - - Encryption Decryption self test - - - - - - - -"
              << std::endl
              << "The inputted string: " << asciiToHex(str) << std::endl
              << "The outputted string: " << bytesToHex(decrypt) << std::endl
              << "STRCMP returned " << strresult << std::endl
              << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
              << std::endl;
    delete key;
    OPENSSL_cleanup();
    return 0;
}
