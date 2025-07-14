#include "inc/crypto/rsa.hpp"
#include "inc/hash/hash.hpp"
#include "inc/math/primes.hpp"
#include "inc/utils/bytes.hpp"
#include "inc/utils/logger.hpp"
#include "inc/utils/time.hpp"
#include <algorithm>
#include <iterator>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <print>
#include <stdio.h>
#include <vector>

RSA_CRT_Params::RSA_CRT_Params()
{
    dp = BN_secure_new(), dq = BN_secure_new(), qInv = BN_secure_new(),
    p = BN_secure_new(), q = BN_secure_new();
    enabled = true;
}

RSA_CRT_Params::~RSA_CRT_Params()
{
    BN_clear_free(this->dp);
    BN_clear_free(this->qInv);
    BN_clear_free(this->dq);
    BN_clear_free(this->p);
    BN_clear_free(this->q);
}

cRSAKey::~cRSAKey()
{
    BN_clear_free(this->d);
    BN_clear_free(this->e);
    BN_clear_free(this->n);
}

cRSAKey::cRSAKey()
{
    this->kBits = 4096;
    this->n = BN_secure_new(), this->e = BN_secure_new(),
    this->d = BN_secure_new();
    this->padding.mode = RSA_Padding::NONE;
}

void cRSAKey::reset()
{
    this->padding.mode = RSA_Padding::NONE;
    this->padding.hashMode = DIGEST_MODE::NONE;
    this->padding.maskHashMode = DIGEST_MODE::NONE;
    this->padding.label.clear();
}

/* Make sure that k = (k^e)^d mod n ; for some int k where 1 < k < n-1 */
int rsa_sp800_56b_pairwise_test(cRSAKey &key)
{
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
// Returns 0 on success of pairwise
int gen_rsa_sp800_56b(cRSAKey &key, bool constTime)
{
    /* FIPS requires the bit length to be within 17-256 */
    if (!(BN_is_odd(key.e) && BN_num_bits(key.e) > 16 &&
          BN_num_bits(key.e) < 257))
    {
        return -1;
    }

    Timer t;
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;

    BN_CTX_start(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    lcm = BN_CTX_get(ctx);
    p1q1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);

    if (constTime)
    {
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

    /* Step 1: Find the least common multiple of (p-1, q-1) */
    BN_sub(p1, key.crt.p, BN_value_one()); /* p - 1 */
    BN_sub(q1, key.crt.q, BN_value_one()); /* q - 1 */
    BN_mul(p1q1, p1, q1, ctx);             /* (p-1)(q-1)*/
    BN_gcd(gcd, p1, q1, ctx);
    BN_div(lcm, NULL, p1q1, gcd, ctx);

    LOG_RSA("P {}", key.crt.p);
    LOG_RSA("Q {}", key.crt.p);
    LOG_RSA("E {}", key.e);
    LOG_RSA("GCD {}", gcd);
    LOG_RSA("LCM {}", lcm);

    /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
    /* Keep repeating incase the bitsize is too short */
    /* Not compliant since will show D failures if the loop continues. Need to
     * finish function and return a value to show failure to restart. */

        for (;;)
        {
            BN_mod_inverse(key.d, key.e, lcm, ctx);
            LOG_RSA("D {}", key.d);
#ifdef DO_CHECKS
            if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
                break;
#else
            break;
#endif
        }

        if (BN_is_zero(key.d) || BN_num_bits(key.d) < key.kBits / 4)
        {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return -1;
        }

        /* Step 3: n = pq */
        BN_mul(key.n, key.crt.p, key.crt.q, ctx);
        LOG_RSA("N {}", key.n);

    t.start();
    /* Step 4: dP = d mod(p-1)*/
    BN_mod(key.crt.dp, key.d, p1, ctx);

    /* Step 5: dQ = d mod(q-1)*/
    BN_mod(key.crt.dq, key.d, q1, ctx);

    /* Step 6: qInv = q^(-1) mod(p) */
    BN_mod_inverse(key.crt.qInv, key.crt.q, key.crt.p, ctx);
    LOG_RSA("DP {}", key.crt.dp);
    LOG_RSA("DQ {}", key.crt.dq);
    LOG_RSA("QINV {}", key.crt.qInv);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return !(rsa_sp800_56b_pairwise_test(key));
}

void BN_strtobn(BIGNUM *bn, std::string &str)
{
    BIGNUM *bnVal = BN_new();
    BN_hex2bn(&bnVal, str.c_str());
    BN_copy(bn, bnVal);
    BN_free(bnVal);
}

void RSA_AddOAEP(cRSAKey &key, std::span<const uint8_t> label, DIGEST_MODE hashMode, DIGEST_MODE maskHashMode)
{
    key.padding.mode = RSA_Padding::OAEP;
    key.padding.label.clear();
    std::copy(label.begin(), label.end(), std::back_inserter(key.padding.label));
    key.padding.hashMode = hashMode;
    key.padding.maskHashMode = maskHashMode;
}

// Permanently setting to auxMode for now.
void RSA_GenerateKey(cRSAKey &key,
                     int kBits,
                     std::string N,
                     std::string E,
                     std::string D,
                     std::string ex1,
                     std::string ex2,
                     std::string coef,
                     std::string P,
                     std::string Q)
{
    key.kBits = kBits;
    bool auxMode = true;

    // Check what is provided.
    // If E is not provided ALWAYS set E to 65537
    // If N,D are not provided -> Check if P,Q are provided; if so then generate
    // from the P,Q provided If N,D are provided and not CRT -> Generate CRT If
    // N,D and CRT provided -> Nothing to be done If N,D and P,Q are not
    // provided -> Generate fully new key

    // Decoding
    // Provided<2 && >0 -> Only P,Q given
    // Provided<4 && >2 -> Atleast N,D provided
    // Provided>4       -> CRT Provided
    int provided = 0;

    if (E == "")
    {
        BIGNUM *myE = BN_new();
        BN_set_word(myE, 65537);
        BN_copy(key.e, myE);
        BN_free(myE);
    }
    else
    {
        BN_strtobn(key.e, E);
    }

    if (N != "" && D != "")
    {
        BN_strtobn(key.n, N);
        BN_strtobn(key.d, D);
        provided += 2;
    }

    if (ex1 != "" && ex2 != "" && coef != "")
    {
        BN_strtobn(key.crt.dp, ex1);
        BN_strtobn(key.crt.dq, ex2);
        BN_strtobn(key.crt.qInv, coef);
        provided += 4;
    }

    if (P != "" && Q != "")
    {
        BN_strtobn(key.crt.p, P);
        BN_strtobn(key.crt.q, Q);
        provided++;
    }

    if (provided < 1)
    {
        // Nothing is provided
        FIPS186_4_GEN_PRIMES(key.crt.p, key.crt.q, key.e,
                             kBits); // true, &ACVP_TEST
        if(gen_rsa_sp800_56b(key, true))
        {
            LOG_ERROR("FAILED TO GENERATE CRT {}", __LINE__);
        }

    }
    else if (provided > 2)
    {
        //N, E, D, and the primes were given
        if(gen_rsa_sp800_56b(key, true))
        {
            LOG_ERROR("FAILED TO GENERATE CRT {}", __LINE__);
        }
    }
    else if (provided == 2)
    {
        // N, E, D are provided, but we don't have the primes. Cannot proceed with CRT
        key.crt.enabled = false;
    }
}

std::vector<uint8_t> mgf1(std::span<const uint8_t> seed,
                          size_t maskLen,
                          DIGEST_MODE shaMode)
{
    std::vector<uint8_t> mask;
    mask.reserve(maskLen);

    long counter = 0;

    // Iterate over the full seed by comparing masklen to the mask array size
    while (mask.size() < maskLen)
    {

        std::vector<uint8_t> T(seed.begin(), seed.end());
        T.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        T.push_back(static_cast<uint8_t>((counter & 0xFF)));

        std::vector<uint8_t> hash = Hasher::hash(T, shaMode);
        mask.insert(mask.end(), hash.begin(), hash.end());

        counter++;
        if (counter == 0)
        {
            LOG_ERROR("{} overflow error", __func__);
        }
    }

    mask.resize(maskLen);
    return mask;
}

std::vector<uint8_t> RSA_Encrypt_Primative(cRSAKey &key,
                                           std::span<const uint8_t> src)
{
    BN_CTX *ctx = BN_CTX_secure_new();

    // RSA block size
    unsigned int maxBytes = key.kBits / 8;
    // Ceiling division
    unsigned int numPages = (src.size() + maxBytes - 1) / maxBytes;
    std::vector<uint8_t> returnData;
    returnData.reserve(numPages * maxBytes);

    for (unsigned int i = 0; i < numPages; ++i)
    {
        BN_CTX_start(ctx);

        // Get block of input data
        size_t blockSize = std::min(
            maxBytes, static_cast<unsigned int>(src.size()) - i * maxBytes);
        const uint8_t *blockStart = src.data() + i * maxBytes;

        // Convert to BIGNUM
        BIGNUM *originalNumber = BN_CTX_get(ctx);
        BN_bin2bn(blockStart, blockSize, originalNumber);
        LOG_RSA("{} Original number: {}", __func__, originalNumber);

        // Encrypt
        BIGNUM *cipherNumber = BN_CTX_get(ctx);
        BN_mod_exp(cipherNumber, originalNumber, key.e, key.n, ctx);
        LOG_RSA("{} Encrypted number: {}", __func__, cipherNumber);

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

std::vector<uint8_t> RSA_Decrypt_Primative(cRSAKey &key,
                                           std::span<const uint8_t> cipher)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    bool errorRaised = false;

    size_t k = key.kBits / 8;
    // RSA block size
    unsigned int maxBytes = k; // key.kBits / 8;

    // Assume cipher is multiple of maxBytes
    unsigned int numPages = cipher.size() / maxBytes;

    if (cipher.size() % maxBytes != 0)
    {
        BN_CTX_free(ctx);

        // Invalid cipher length
        return {};
    }

    std::vector<uint8_t> returnData;

    // Preallocate for efficiency
    returnData.reserve(numPages * maxBytes);
    for (unsigned int i = 0; i < numPages; i++)
    {
        BN_CTX_start(ctx);

        // Convert cipher block to BIGNUM
        BIGNUM *cipherNumber = BN_CTX_get(ctx);
        BN_bin2bn(cipher.data() + i * maxBytes, maxBytes, cipherNumber);

        if(BN_cmp(cipherNumber, key.n) == 0 || BN_cmp(cipherNumber, key.n) == 1)
        {
            //Failure;
            errorRaised = true;
            goto Error;
        }

        // Decrypt
        BIGNUM *decryptedNumber = BN_CTX_get(ctx);
        if (key.crt.enabled)
        {
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
            BN_add(decryptedNumber, m2, hq);
        }
        else
        {
            // Standard decryption: m = c^d mod n
            BN_mod_exp(decryptedNumber, cipherNumber, key.d, key.n, ctx);
        }

        LOG_RSA("Decrypted numbers: {}", decryptedNumber);

        // Convert decrypted data to binary
        std::vector<uint8_t> decryptedBlock(k);
        BN_bn2binpad(decryptedNumber, decryptedBlock.data(), k);
        returnData.insert(returnData.end(), decryptedBlock.begin(),
                          decryptedBlock.end());
        BN_CTX_end(ctx);
    }

Error:
    if (errorRaised)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return {};
    }
    BN_CTX_free(ctx);
    return returnData;
}

// NIST SP800-56B 7.2.2.3
ByteArray OAEP_Encode(cRSAKey &key,
                      std::span<const uint8_t> msg,
                      std::span<uint8_t> seed,
                      bool givenSeed)
{
    const size_t kLen = msg.size(); // Msg length
    const size_t nLen = key.kBits / 8;

    // Step A
    ByteArray lHash = Hasher::hash(key.padding.label, key.padding.hashMode);

    const size_t hLen = lHash.size(); 

    if (kLen > (nLen - (2 * hLen) - 2))
    {
        // Todo: indicate error
        std::print("{} {} error occured.", __FILE_NAME__, __LINE__);
    }


    // Step B
    size_t psLen = nLen - kLen - (2 * hLen) - 2;
    ByteArray PS(psLen, 0x00);

    // Step C
    //  DB = HA || PS || 00000001 || K
    ByteArray DB;
    DB.insert(DB.end(), lHash.begin(), lHash.end());
    DB.insert(DB.end(), PS.begin(), PS.end());
    DB.push_back(0x01);
    DB.insert(DB.end(), msg.begin(), msg.end());

    // Step D
    if (!givenSeed)
    {
        //seed.resize(hLen);
        ByteArray _seed(hLen);
        RAND_bytes(_seed.data(), hLen);
        seed = _seed;
    }

    // Step E
    ByteArray dbMask = mgf1(seed, nLen - hLen - 1, key.padding.maskHashMode);

    // Step F
    ByteArray maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); i++)
    {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    // Step G
    ByteArray seedMask = mgf1(maskedDB, hLen, key.padding.maskHashMode);

    // Step H
    ByteArray maskedSeed(hLen);
    for (size_t i = 0; i < hLen; i++)
    {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    // Step I
    //  EM = 00000000 || maskedMGFSeed || maskedDB
    ByteArray EM;
    EM.push_back(0x00);
    EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
    return EM;
}


// NIST SP800-56B 7.2.2.4
ByteArray OAEP_Decode(cRSAKey &key, std::span<const uint8_t> EM)
{
    const size_t nLen = key.kBits / 8;

    // Step A
    ByteArray HA = Hasher::hash(key.padding.label, key.padding.hashMode);

    const size_t hLen =  HA.size();
    bool decryptionError = false;

    //Initial check to see if Decrypt failed
    if(EM.empty())
    {
        decryptionError = true;
        return ByteArray();
    }

    // Confirm correct size and that the first bit is padded
    if (EM[0] != 0x00)
    {
        decryptionError = true;
    }

    if (EM.size() != nLen)
    {
        decryptionError = true;
    }


    // Step B
    const uint8_t *pMaskedSeed = EM.data() + 1; // Pulls the masked MGFSeed disregarding the 0x00
    const uint8_t *pMaskedDB = EM.data() + 1 + hLen; // Pulls the maskedDB skips hLen (seed hash) +1 0x00

    ByteArray maskedSeed(pMaskedSeed, pMaskedSeed + hLen);
    ByteArray maskedDB(pMaskedDB, pMaskedDB + (nLen - hLen - 1));

    // Step C
    ByteArray msgSeedMask = mgf1(maskedDB, hLen, key.padding.maskHashMode);

    // Step D
    ByteArray seed(hLen);
    for (size_t i = 0; i < hLen; i++)
    {
        seed[i] = maskedSeed[i] ^ msgSeedMask[i];
    }

    // Step E
    ByteArray dbMask = mgf1(seed, nLen - hLen - 1, key.padding.maskHashMode);

    // Step F
    ByteArray DB(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); i++)
    {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    // Step G
    if (!std::equal(DB.begin(), DB.begin() + hLen, HA.begin()))
    {
        // Label is incorrect (HA)
        decryptionError = true;
    }

    // Check the formatting
    size_t index = hLen;
    while (index < DB.size())
    {
        if (DB[index] == 0x01)
        {
            index++;
            break;
        }

        if (DB[index] != 0x00)
        {
            decryptionError = true; // Padding is incorrect
        }
        index++;
    }

    if (index >= DB.size())
    {
        decryptionError = true; // Did not find the 0x01
    }

    if (!decryptionError)
    {
        ByteArray msg(DB.begin() + index, DB.end());
        return msg;
    }
    else
    {
        // We do not immediately jump here so we can obfuscate what the error
        // cause was
        ByteArray msg = {};
        return msg;
    }
}

std::vector<uint8_t> RSA_Encrypt(cRSAKey &key, std::span<const uint8_t> src)
{
    if (key.padding.mode == RSA_Padding::OAEP)
    {
        // TODO: Storing so that we can later log this for creating tests
        ByteArray seed;
        return RSA_Encrypt_Primative(key, OAEP_Encode(key, src, seed, false));
    }
    else
    {
        return RSA_Encrypt_Primative(key, src);
    }
}

std::vector<uint8_t> RSA_Decrypt(cRSAKey &key, std::span<const uint8_t> cipher)
{
    if (key.padding.mode == RSA_Padding::OAEP)
    {
        ByteArray EM = RSA_Decrypt_Primative(key, cipher);
        return OAEP_Decode(key, EM);
    }
    else
    {
        return RSA_Decrypt_Primative(key, cipher);
    }
}
