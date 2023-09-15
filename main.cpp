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
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <openssl/rand.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "inc/defs.hpp"
#include "inc/utils/logger.hpp"
#include "inc/crypto/rsa.hpp"
#include "inc/math/primes.hpp"
#include "inc/math/rand.hpp"
#include "inc/hash/sha.hpp"
#include "inc/tests/test.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/crypto/ec.hpp"
#include "inc/utils/time.hpp"
#include "inc/crypto/aes.hpp"
#include "inc/utils/bytes.hpp"
#include <cstdio>
#include <stdexcept>
#include <memory>

int main(int argc, char *argv[])
{
    AES_CTX *ctx = new AES_CTX();
    ctx->mode = AES_CBC_128;
    FIPS_197_5_2_KeyExpansion(ctx, scanHex("2b7e151628aed2a6abf7158809cf4f3c", 128 / 8));
    SetIV(ctx, scanHex("000102030405060708090a0b0c0d0e0f", 16));
    uint8_t *outA = (uint8_t *)malloc(64);
    uint8_t *outB = (uint8_t *)malloc(64);

    CBC_Encrypt(ctx, outA, scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64), 64);
    printf("CBC Encrypt: %s\n", printWord(outA, 64, 16));
    CBC_Decrypt(ctx, outB, outA, 64);
    printf("CBC Decrypt: %s\n", printWord(outB, 64, 16));
    if (!memcmp(scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64), outB, 64))
        printf("CBC passed!\n");
    else
        printf("CBC failed.\n");

    memset(outA, 0, 64);
    memset(outB, 0, 64);

    SetIV(ctx, scanHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 16));
    CTR_xcrypt(ctx, outA, scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64), 64);
    printf("CTR Encrypt: %s\n", printWord(outA, 64, 16));

    CTR_xcrypt(ctx, outB, outA, 64);
    printf("CTR Decrypt: %s\n", printWord(outB, 64, 16));
    if (!memcmp(scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64), outB, 64))
        printf("CTR Decrypt passed!\n");
    else
        printf("CTR Decrypt failed.\n");

    for (int i = 0; i < 64; i++)
    {
        if (outB[i] != scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64)[i])
        {
            printf("Failure found on %d: %02x %02x\n", i, outB[i], scanHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64)[i]);
        }
    }

    return 0;
}