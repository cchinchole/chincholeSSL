#include "inc/crypto/rsa.hpp"
#include "inc/defs.hpp"
#include "inc/hash/sha.hpp"
#include "inc/math/primes.hpp"
#include "inc/utils/logger.hpp"
#include "inc/utils/time.hpp"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include <algorithm>

RSA_CRT_Params::RSA_CRT_Params() {
    dp = BN_secure_new(), dq = BN_secure_new(), qInv = BN_secure_new(),
    p = BN_secure_new(), q = BN_secure_new();
}

RSA_CRT_Params::~RSA_CRT_Params() {
    BN_clear_free(this->dp);
    BN_clear_free(this->qInv);
    BN_clear_free(this->dq);
    BN_clear_free(this->p);
    BN_clear_free(this->q);
}

cRSAKey::~cRSAKey() {
    BN_clear_free(this->d);
    BN_clear_free(this->e);
    BN_clear_free(this->n);
    //delete this->crt;
}

cRSAKey::cRSAKey() {
    this->kBits = 4096;
    this->n = BN_secure_new(), this->e = BN_secure_new(),
    this->d = BN_secure_new();
    //this->crt = new RSA_CRT_Params();
}

/* Make sure that k = (k^e)^d mod n ; for some int k where 1 < k < n-1 */
int rsa_sp800_56b_pairwise_test(cRSAKey &key) {
    BIGNUM *k, *tmp;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    /* First set k to 2 (between 1 < n-1 ) then take ( k^e mod n )^d mod n and
     * compare k to tmp */
    int ret = (BN_set_word(k, 2) && BN_mod_exp(tmp, k, key.e, key.n, ctx) &&
               BN_mod_exp(tmp, tmp, key.d, key.n, ctx) && !BN_cmp(k, tmp));
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

/* Computes d, n, dP, dQ, qInv from the prime factors and public exponent */
int gen_rsa_sp800_56b(cRSAKey &key, bool constTime) {
    /* FIPS requires the bit length to be within 17-256 */
    if (!(BN_is_odd(key.e) && BN_num_bits(key.e) > 16 &&
          BN_num_bits(key.e) < 257)) {
        return -1;
    }

    Timer t;
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;
    Logger *_Logger = new Logger();

    BN_CTX_start(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    lcm = BN_CTX_get(ctx);
    p1q1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);

    if (constTime) {
        BN_set_flags(p1, BN_FLG_CONSTTIME);
        BN_set_flags(q1, BN_FLG_CONSTTIME);
        BN_set_flags(lcm, BN_FLG_CONSTTIME);
        BN_set_flags(p1q1, BN_FLG_CONSTTIME);
        BN_set_flags(gcd, BN_FLG_CONSTTIME);
        BN_set_flags(key.d, BN_FLG_CONSTTIME);
        /* Note: N is not required to be constant time. */
        BN_set_flags(key.crt.dp, BN_FLG_CONSTTIME);
        BN_set_flags(key.crt.dq, BN_FLG_CONSTTIME);
        BN_set_flags(key.crt.qInv, BN_FLG_CONSTTIME);
    }

    _Logger->parameter("P", key.crt.p);
    _Logger->parameter("Q", key.crt.q);
    _Logger->parameter("E", key.e);

    /* Step 1: Find the least common multiple of (p-1, q-1) */
    BN_sub(p1, key.crt.p, BN_value_one()); /* p - 1 */
    BN_sub(q1, key.crt.q, BN_value_one()); /* q - 1 */
    BN_mul(p1q1, p1, q1, ctx);               /* (p-1)(q-1)*/
    BN_gcd(gcd, p1, q1, ctx);
    BN_div(lcm, NULL, p1q1, gcd, ctx);

    _Logger->parameter("GCD", gcd);
    _Logger->parameter("LCM", lcm);

    /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
    /* Keep repeating incase the bitsize is too short */
    /* Not compliant since will show D failures if the loop continues. Need to
     * finish function and return a value to show failure to restart. */

    for (;;) {
        BN_mod_inverse(key.d, key.e, lcm, ctx);
        _Logger->parameter("D", key.d);
#ifdef DO_CHECKS
        if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
            break;
#else
        break;
#endif
    }

    if (BN_is_zero(key.d) || BN_num_bits(key.d) < key.kBits / 4) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return -1;
    }

    /* Step 3: n = pq */
    BN_mul(key.n, key.crt.p, key.crt.q, ctx);
    _Logger->parameter("N", key.n);

    t.start();
    /* Step 4: dP = d mod(p-1)*/
    BN_mod(key.crt.dp, key.d, p1, ctx);

    /* Step 5: dQ = d mod(q-1)*/
    BN_mod(key.crt.dq, key.d, q1, ctx);

    /* Step 6: qInv = q^(-1) mod(p) */
    BN_mod_inverse(key.crt.qInv, key.crt.q, key.crt.p, ctx);

    printf("Took: %dms to generate CRT parameters.\n", t.getElapsed(true));

    _Logger->parameter("DP", key.crt.dp);
    _Logger->parameter("DQ", key.crt.dq);
    _Logger->parameter("QINV", key.crt.qInv);

    if (rsa_sp800_56b_pairwise_test(key))
        printf("Pairwise passed!\n");
    else
        printf("Pairwise failed!\n");

    delete _Logger;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

void RSA_GenerateKey(cRSAKey &key, BIGNUM *e, int kBits, bool auxMode) {
    key.kBits = kBits;
    if (!e) {
        BIGNUM *myE = BN_new();
        BN_set_word(myE, 0x100000001);
        BN_copy(key.e, myE);
        BN_free(myE);
    } else {
        BN_copy(key.e, e);
    }

    if (auxMode) {
        ACVP_TEST test = {
            NULL, NULL,       /* XP Out, XQ Out */
            NULL, NULL, NULL, /* XP, XP1, XP2*/
            NULL, NULL, NULL, /* XQ, XQ1, XQ2 */
            NULL, NULL,       /* P1, P2 */
            NULL, NULL,       /* Q1, Q2 */
        };

        FIPS186_4_GEN_PRIMES(key.crt.p, key.crt.q, key.e, kBits, true,
                             &test);
        gen_rsa_sp800_56b(key, true);
    } else {
        generatePrimes(key.crt.p, key.crt.q, key.e, kBits, 0);
        if (gen_rsa_sp800_56b(key, true) != 0)
            printf("Failed to gen\n");
    }
}

/* TODO : Move this to more suitable place */
std::vector<uint8_t> sha_hash(std::vector<uint8_t> &input, SHA_MODE mode) {
    std::vector<uint8_t> hash;
    hash.resize(getSHAReturnLengthByMode(mode));
    SHA_Context *ctx = SHA_Context_new(mode);
    sha_update(input.data(), input.size(), ctx);
    sha_digest(hash.data(), ctx);
    delete ctx;
    return hash;
}

std::vector<uint8_t> mgf1(const std::vector<uint8_t> &seed, size_t maskLen,
                          SHA_MODE shaMode) {
    const size_t hLen = getSHAReturnLengthByMode(shaMode);
    std::vector<uint8_t> mask;
    mask.reserve(maskLen);

    long counter = 0;

    // Iterate over the full seed by comparing masklen to the mask array size 
    while (mask.size() < maskLen) {

        std::vector<uint8_t> T = seed;
        T.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter & 0xFF)));

        printf("T: %d\n", T.size());
        // TODO : Make this work for any sha implementation.
        std::vector<uint8_t> hash = sha_hash(T, shaMode);
        mask.insert(mask.end(), hash.begin(), hash.end());
        
        counter++;
        if (counter == 0) {
            // TODO: Implement error here 
            throw std::overflow_error("MGF1 Overflowed");
        }
    }

    mask.resize(maskLen);
    return mask;
}

std::vector<uint8_t> RSA_Encrypt(cRSAKey &key,
                                 const std::vector<uint8_t> &src) {
    BN_CTX *ctx = BN_CTX_secure_new();

    // RSA block size
    unsigned int maxBytes = key.kBits / 8;
    // Ceiling division
    unsigned int numPages = (src.size() + maxBytes - 1) / maxBytes;
    std::vector<uint8_t> returnData;
    returnData.reserve(numPages * maxBytes);

    for (unsigned int i = 0; i < numPages; ++i) {
        BN_CTX_start(ctx);

        // Get block of input data
        size_t blockSize = std::min(
            maxBytes, static_cast<unsigned int>(src.size()) - i * maxBytes);
        const uint8_t *blockStart = src.data() + i * maxBytes;

        // Convert to BIGNUM
        BIGNUM *originalNumber = BN_CTX_get(ctx);
        BN_bin2bn(blockStart, blockSize, originalNumber);
#ifdef LOG_CRYPTO
// TODO: FIX THIS
// std::cout << "Original Number: " << BN_bn2dec(originalNumber) << std::endl;
#endif

        // Encrypt
        BIGNUM *cipherNumber = BN_CTX_get(ctx);
        BN_mod_exp(cipherNumber, originalNumber, key.e, key.n, ctx);
#ifdef LOG_CRYPTO
        // TODO: FIX THIS
        // std::cout << "Encrypted Number: " << BN_bn2dec(cipherNumber) <<
        // std::endl << std::endl;
#endif

        // Convert cipher to binary
        std::vector<uint8_t> cipherBlock(BN_num_bytes(cipherNumber));
        BN_bn2bin(cipherNumber, cipherBlock.data());
        returnData.insert(returnData.end(), cipherBlock.begin(),
                          cipherBlock.end());

        BN_CTX_end(ctx);
    }

    BN_CTX_free(ctx);
    return returnData;
}

std::vector<uint8_t> RSA_Decrypt(cRSAKey &key,
                                 const std::vector<uint8_t> &cipher, bool crt) {
    BN_CTX *ctx = BN_CTX_secure_new();
    bool errorRaised = false;

    // RSA block size
    unsigned int maxBytes = key.kBits / 8;

    // Assume cipher is multiple of maxBytes
    unsigned int numPages = cipher.size() / maxBytes;

    if (cipher.size() % maxBytes != 0) {
        BN_CTX_free(ctx);

        // Invalid cipher length
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> returnData;

    // Preallocate for efficiency
    returnData.reserve(numPages * maxBytes);
    for (unsigned int i = 0; i < numPages; ++i) {
        BN_CTX_start(ctx);

        // Convert cipher block to BIGNUM
        BIGNUM *cipherNumber = BN_CTX_get(ctx);
        BN_bin2bn(cipher.data() + i * maxBytes, maxBytes, cipherNumber);

        // Decrypt
        BIGNUM *decryptedData = BN_CTX_get(ctx);
        if (crt) {
            // CRT Decryption
            BIGNUM *m1 = BN_CTX_get(ctx);
            BIGNUM *m2 = BN_CTX_get(ctx);
            BIGNUM *h = BN_CTX_get(ctx);
            BIGNUM *m1subm2 = BN_CTX_get(ctx);
            BIGNUM *hq = BN_CTX_get(ctx);

            // m1 = c^(dP) mod p
            BN_mod_exp(m1, cipherNumber, key.crt.dp, key.crt.p, ctx);

            // m2 = c^(dQ) mod q
            BN_mod_exp(m2, cipherNumber, key.crt.dq, key.crt.q, ctx);

            // m1subm2 = (m1 - m2)
            BN_sub(m1subm2, m1, m2);

            // h = qInv * (m1subm2) mod p
            BN_mod_mul(h, key.crt.qInv, m1subm2, key.crt.p, ctx);

            // hq = h * q
            BN_mul(hq, h, key.crt.q, ctx);

            // m = m2 + h * q
            BN_add(decryptedData, m2, hq);
        } else {
            // Standard decryption: m = c^d mod n
            BN_mod_exp(decryptedData, cipherNumber, key.d, key.n, ctx);
        }
#ifdef LOG_CRYPTO
// TOOD: FIX THIS
// std::cout << "Decrypted Numbers: " << BN_bn2dec(decryptedData) << std::endl
// << std::endl;
#endif

        // Convert decrypted data to binary
        std::vector<uint8_t> decryptedBlock(BN_num_bytes(decryptedData));
        BN_bn2bin(decryptedData, decryptedBlock.data());
        returnData.insert(returnData.end(), decryptedBlock.begin(),
                          decryptedBlock.end());
        BN_CTX_end(ctx);
    }

Error:
    if (errorRaised) {
        BN_CTX_end(ctx);
        return std::vector<uint8_t>();
    }
    BN_CTX_free(ctx);
    return returnData;
}


