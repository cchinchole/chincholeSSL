#include "../inc/crypto/rsa.hpp"
#include "../inc/utils/bytes.hpp"
#include "../inc/utils/logger.hpp"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <print>

int main()
{
    // Setting a key via the values key reference, public exponent, prime1,
    // prime2
    cRSAKey key;

    // Example provided the bits, N, E, D
    RSA_GenerateKey(
        key, 1024,
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0"
        "b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40b"
        "f25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae"
        "1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
        "010001",
        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258d"
        "f93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df4157"
        "0926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04"
        "724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1");

    //Key, Padding Mode, Label, Label Digest, MGF Digest
    RSA_SetPaddingMode(key, RSA_Padding::OAEP, {}, DIGEST_MODE::SHA_1, DIGEST_MODE::SHA_1);

    ByteArray str = {0x66, 0x28, 0x19, 0x4e, 0x12, 0x07, 0x3d, 0xb0, 0x3b, 0xa9,
                     0x4c, 0xda, 0x9e, 0xf9, 0x53, 0x23, 0x97, 0xd5, 0x0d, 0xba,
                     0x79, 0xb9, 0x87, 0x00, 0x4a, 0xfe, 0xfe, 0x34};

    ByteArray seed = {0x18, 0xb7, 0x76, 0xea, 0x21, 0x06, 0x9d,
                      0x69, 0x77, 0x6a, 0x33, 0xe9, 0x6b, 0xad,
                      0x48, 0xe1, 0xdd, 0xa0, 0xa5, 0xef};
    std::println("Values generated via primes: ");
    std::println("Key N: {}", key.n);
    std::println("Key E: {}", key.e);
    std::println("Key D: {}", key.d);
    std::println("Key CRT Enabled: {}", key.crt.enabled);
    std::println("Key E1: {}", key.crt.dp);
    std::println("Key E2: {}", key.crt.dq);
    std::println("Key QInv: {}", key.crt.qInv);

    // If you want to manually specify a seed, for testing, you must OAEP encode
    // and specify the seed. Then call the RSA Primitive yourself.
    std::vector<uint8_t> emBeforeCipher = OAEP_Encode(key, str, seed, true);
    ByteArray cipher = RSA_Encrypt_Primative(key, emBeforeCipher);
    // std::vector<uint8_t> cipher = RSA_Encrypt(key, str);
    std::println("Cipher after OAEP: {}", cipher);
    std::println("After decode: {}", (RSA_Decrypt(key, cipher)));

    // Generating a new key
    RSA_GenerateKey(key, 4096);
    RSA_SetPaddingMode(key, RSA_Padding::NONE);

    cipher.clear();
    cipher = RSA_Encrypt(key, str);
    std::vector<uint8_t> decrypt = RSA_Decrypt(key, cipher);
    decrypt = stripPadding(decrypt);
    int strresult = ((std::equal(decrypt.begin(), decrypt.end(), str.begin(), str.end())));
    std::println(
        "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
    std::println("The inputted string: {}", str);
    std::println("The outputted string: {}", decrypt);
    std::println("STRCMP returned {}", strresult);
    std::println(
        "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
    OPENSSL_cleanup();
    return !strresult; //Return 1 on failure and 0 on success
}
