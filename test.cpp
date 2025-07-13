#include "inc/tests/test.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/hash/sha.hpp"
#include "inc/math/primes.hpp"
#include "inc/utils/bytes.hpp"
#include <math.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

/* Returns the discrepancies between the functions */
int testPrimesBetweenFuncs()
{
    BIGNUM *testPrime = BN_secure_new();
    int s = 0, j = 0;
    for (int i = 4; i < 17863; i++)
    {
        BN_set_word(testPrime, i);
        if (miller_rabin_is_prime(testPrime, 64))
            if (BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
                s++;
            else
                j++;
        else if (BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
            j++;
    }
    printf("Primes found: %d Discrepancies between other func: %d\n", s, j);
    BN_free(testPrime);

    return j;
}

/* Returns 0 on success */
int testSHA_Shake(char *msg,
                  size_t msg_len,
                  std::string KAT,
                  DIGEST_MODE mode,
                  size_t digestSize,
                  bool quiet)
{
    SHA_3_Context *ctx = (SHA_3_Context *)SHA_Context_new(mode);
    unsigned char rawDigest[digestSize / 8];
    SHA_Update((uint8_t *)msg, msg_len, ctx);
    SHA_3_xof(ctx);
    SHA_3_shake_digest(rawDigest, digestSize / 8, ctx);
    std::string hexString = bytesToHex(bytePtrToVector(rawDigest, digestSize));

    int res = (hexString == KAT);
    if (!quiet)
        res == 0 ? printf("(%s Test) HASH Returned: %s PASSED!\n",
                          DIGEST_MODE_NAME(mode), hexString.c_str())
                 : printf("(%s Test) HASH Returned: %s FAILED!\n",
                          DIGEST_MODE_NAME(mode), hexString.c_str());

    return res;
}

/* Returns 0 on success */
int testSHA(char *msg, size_t msg_len, char *KAT, DIGEST_MODE mode, bool quiet)
{
    SHA_Context *ctx = SHA_Context_new(mode);
    unsigned char rawDigest[getSHAReturnLengthByMode(ctx->mode)];

    SHA_Update((uint8_t *)msg, msg_len, ctx);
    SHA_Digest(rawDigest, ctx);

    std::vector<uint8_t> vec =
        bytePtrToVector(rawDigest, getSHAReturnLengthByMode(ctx->mode));
    std::string hexString = bytesToHex(vec);
    int res = strcasecmp((char *)hexString.c_str(), KAT);
    if (!quiet)
        res == 0 ? printf("(%s Test) HASH Returned: %s PASSED!\n",
                          DIGEST_MODE_NAME(mode), hexString.c_str())
                 : printf("(%s Test) HASH Returned: %s FAILED!\n",
                          DIGEST_MODE_NAME(mode), hexString.c_str());

    delete ctx;
    return res;
}

/* Returns 0 on success */
int testHMAC(char *msg,
             size_t msg_len,
             char *key,
             size_t key_len,
             char *KAT,
             DIGEST_MODE mode,
             bool quiet)
{
    unsigned char rawDigest[getSHAReturnLengthByMode(mode)];
    SHA_Context *ctx = SHA_Context_new(mode);
    hmac_sha(ctx, rawDigest, (unsigned char *)msg, msg_len,
             (unsigned char *)key, key_len);

    std::string hexString = bytesToHex(
        bytePtrToVector(rawDigest, getSHAReturnLengthByMode(ctx->mode)));
    int res = strcasecmp(hexString.c_str(), KAT);
    if (!quiet)
    {
        res == 0 ? printf("(HMAC [ %s ] Test) HASH Returned: %s PASSED!\n",
                          DIGEST_MODE_NAME(DIGEST_MODE(mode)), hexString.c_str())
                 : printf("HASH Returned: %s FAILED!\n", hexString.c_str());
    }
    return res;
}
