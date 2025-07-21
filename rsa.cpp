#include "internal/rsa.hpp"
#include "inc/math/primes.hpp"
#include "inc/utils/bytes.hpp"
#include "inc/utils/logger.hpp"
#include "inc/utils/time.hpp"
#include "inc/hash/hash.hpp"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdio.h>

using namespace cssl;

// Make sure that k = (k^e)^d mod n ; for some int k where 1 < k < n-1
// gen_rsa_sp800_56b
int rsa_pairwise_test(RsaKey &key)
{
    BIGNUM *k, *tmp;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    // First set k to 2 (between 1 < n-1 ) then take ( k^e mod n )^d mod n and
    // compare k to tmp
    int ret = (BN_set_word(k, 2) && BN_mod_exp(tmp, k, key.e_, key.n_, ctx) &&
               BN_mod_exp(tmp, tmp, key.d_, key.n_, ctx) && !BN_cmp(k, tmp));
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

// Computes d, n, dP, dQ, qInv from the prime factors and public exponent
// gen_rsa_sp800_56b
// Returns 0 on success of pairwise
int rsa_gen_crt_params(RsaKey &key, bool constTime)
{
    /* FIPS requires the bit length to be within 17-256 */
    if (!(BN_is_odd(key.e_) && BN_num_bits(key.e_) > 16 &&
          BN_num_bits(key.e_) < 257))
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
        BN_set_flags(key.d_, BN_FLG_CONSTTIME);
        /* Note: N is not required to be constant time. */
        BN_set_flags(key.crt_params_.dp_, BN_FLG_CONSTTIME);
        BN_set_flags(key.crt_params_.dq_, BN_FLG_CONSTTIME);
        BN_set_flags(key.crt_params_.qinv_, BN_FLG_CONSTTIME);
    }

    /* Step 1: Find the least common multiple of (p-1, q-1) */
    BN_sub(p1, key.crt_params_.p_, BN_value_one()); /* p - 1 */
    BN_sub(q1, key.crt_params_.q_, BN_value_one()); /* q - 1 */
    BN_mul(p1q1, p1, q1, ctx);             /* (p-1)(q-1)*/
    BN_gcd(gcd, p1, q1, ctx);
    BN_div(lcm, NULL, p1q1, gcd, ctx);

    LOG_RSA("P {}", key.crt_params_.p_);
    LOG_RSA("Q {}", key.crt_params_.q_);
    LOG_RSA("E {}", key.e_);
    LOG_RSA("GCD {}", gcd);
    LOG_RSA("LCM {}", lcm);

    /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
    /* Keep repeating incase the bitsize is too short */
    /* Not compliant since will show D failures if the loop continues. Need to
     * finish function and return a value to show failure to restart. */

    for (;;)
    {
        BN_mod_inverse(key.d_, key.e_, lcm, ctx);
        LOG_RSA("D {}", key.d_);
#ifdef DO_CHECKS
        if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
            break;
#else
        break;
#endif
    }

    if (BN_is_zero(key.d_) || BN_num_bits(key.d_) < key.modulus_bits_ / 4)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return -1;
    }

    /* Step 3: n = pq */
    BN_mul(key.n_, key.crt_params_.p_, key.crt_params_.q_, ctx);
    LOG_RSA("N {}", key.n_);

    t.start();
    /* Step 4: dP = d mod(p-1)*/
    BN_mod(key.crt_params_.dp_, key.d_, p1, ctx);

    /* Step 5: dQ = d mod(q-1)*/
    BN_mod(key.crt_params_.dq_, key.d_, q1, ctx);

    /* Step 6: qInv = q^(-1) mod(p) */
    BN_mod_inverse(key.crt_params_.qinv_, key.crt_params_.q_, key.crt_params_.p_, ctx);
    LOG_RSA("DP {}", key.crt_params_.dp_);
    LOG_RSA("DQ {}", key.crt_params_.dq_);
    LOG_RSA("QINV {}", key.crt_params_.qinv_);

    key.crt_params_.enabled_ = true;

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return !(rsa_pairwise_test(key));
}

void rsa_add_oaep(RsaKey &key, ByteSpan label, DIGEST_MODE hashMode,
                 DIGEST_MODE maskHashMode)
{
    key.padding_.mode = RsaPadding::OAEP;
    key.padding_.label.clear();
    std::copy(label.begin(), label.end(),
              std::back_inserter(key.padding_.label));
    key.padding_.label_hash_mode = hashMode;
    key.padding_.hask_hash_mode = maskHashMode;
}

void rsa_add_oaep(RsaKey &key, ByteSpan label, ByteSpan seed,
                 DIGEST_MODE hashMode, DIGEST_MODE maskHashMode)
{
    key.padding_.mode = RsaPadding::OAEP;
    key.padding_.label.clear();
    key.padding_.seed.clear();
    std::copy(label.begin(), label.end(),
              std::back_inserter(key.padding_.label));
    std::copy(seed.begin(), seed.end(), std::back_inserter(key.padding_.seed));
    key.padding_.label_hash_mode = hashMode;
    key.padding_.hask_hash_mode = maskHashMode;
}

// Permanently setting to auxMode for now.
void rsa_generate_key(RsaKey &key, int kBits)
{
    key.modulus_bits_ = kBits;
    bool auxMode = true;

    // Nothing is provided
    BN_set_word(key.e_, 65537);
    gen_primes(key.crt_params_.p_, key.crt_params_.q_, key.e_, kBits);
    if (rsa_gen_crt_params(key, true))
    {
        LOG_ERROR("FAILED TO GENERATE CRT {}", __LINE__);
    }
}

std::vector<uint8_t> rsa_mgf1(std::span<const uint8_t> seed, size_t maskLen,
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

        std::vector<uint8_t> hash = cssl::Hasher::hash(T, shaMode);
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

std::vector<uint8_t> rsa_encrypt_primative(RsaKey &key,
                                           std::span<const uint8_t> src)
{
    BN_CTX *ctx = BN_CTX_secure_new();

    // RSA block size
    unsigned int maxBytes = key.modulus_bits_ / 8;
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
        BN_mod_exp(cipherNumber, originalNumber, key.e_, key.n_, ctx);
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

std::vector<uint8_t> rsa_decrypt_primative(RsaKey &key,
                                           std::span<const uint8_t> cipher)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    bool errorRaised = false;
    size_t k = key.modulus_bits_ / 8;
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

        if (BN_cmp(cipherNumber, key.n_) == 0 ||
            BN_cmp(cipherNumber, key.n_) == 1)
        {
            // Failure;
            errorRaised = true;
            goto Error;
        }

        // Decrypt
        BIGNUM *decryptedNumber = BN_CTX_get(ctx);
        if (key.crt_params_.enabled_)
        {
            // CRT Decryption
            BIGNUM *m1 = BN_CTX_get(ctx);
            BIGNUM *m2 = BN_CTX_get(ctx);
            BIGNUM *h = BN_CTX_get(ctx);
            BIGNUM *m1subm2 = BN_CTX_get(ctx);
            BIGNUM *hq = BN_CTX_get(ctx);

            // m1 = c^(dP) mod p
            BN_mod_exp(m1, cipherNumber, key.crt_params_.dp_, key.crt_params_.p_, ctx);

            // m2 = c^(dQ) mod q
            BN_mod_exp(m2, cipherNumber, key.crt_params_.dq_, key.crt_params_.q_, ctx);

            // m1subm2 = (m1 - m2)
            BN_sub(m1subm2, m1, m2);

            // h = qInv * (m1subm2) mod p
            BN_mod_mul(h, key.crt_params_.qinv_, m1subm2, key.crt_params_.p_, ctx);

            // hq = h * q
            BN_mul(hq, h, key.crt_params_.q_, ctx);

            // m = m2 + h * q
            BN_add(decryptedNumber, m2, hq);
        }
        else
        {
            // Standard decryption: m = c^d mod n
            BN_mod_exp(decryptedNumber, cipherNumber, key.d_, key.n_, ctx);
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
ByteArray rsa_oaep_encode(RsaKey &key, std::span<const uint8_t> msg)
{
    const size_t kLen = msg.size(); // Msg length
    const size_t nLen = key.modulus_bits_ / 8;

    // Step A
    ByteArray lHash = cssl::Hasher::hash(key.padding_.label, key.padding_.label_hash_mode);

    const size_t hLen = lHash.size();

    if (kLen > (nLen - (2 * hLen) - 2))
    {
        // TODO: indicate error
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
    if (key.padding_.seed.empty())
    {
        key.padding_.seed.resize(hLen);
        RAND_bytes(key.padding_.seed.data(), hLen);
    }

    // Step E
    ByteArray dbMask =
        rsa_mgf1(key.padding_.seed, nLen - hLen - 1, key.padding_.hask_hash_mode);

    // Step F
    ByteArray maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); i++)
    {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    // Step G
    ByteArray seedMask = rsa_mgf1(maskedDB, hLen, key.padding_.hask_hash_mode);

    // Step H
    ByteArray maskedSeed(hLen);
    for (size_t i = 0; i < hLen; i++)
    {
        maskedSeed[i] = key.padding_.seed[i] ^ seedMask[i];
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
ByteArray rsa_oaep_decode(RsaKey &key, std::span<const uint8_t> EM)
{
    const size_t nLen = key.modulus_bits_ / 8;

    // Step A
    ByteArray HA = cssl::Hasher::hash(key.padding_.label, key.padding_.label_hash_mode);

    const size_t hLen = HA.size();
    bool decryptionError = false;

    // Initial check to see if Decrypt failed
    if (EM.empty())
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
    const uint8_t *pMaskedSeed =
        EM.data() + 1; // Pulls the masked MGFSeed disregarding the 0x00
    const uint8_t *pMaskedDB =
        EM.data() + 1 +
        hLen; // Pulls the maskedDB skips hLen (seed hash) +1 0x00

    ByteArray maskedSeed(pMaskedSeed, pMaskedSeed + hLen);
    ByteArray maskedDB(pMaskedDB, pMaskedDB + (nLen - hLen - 1));

    // Step C
    ByteArray msgSeedMask = rsa_mgf1(maskedDB, hLen, key.padding_.hask_hash_mode);

    // Step D
    ByteArray seed(hLen);
    for (size_t i = 0; i < hLen; i++)
    {
        seed[i] = maskedSeed[i] ^ msgSeedMask[i];
    }

    // Step E
    ByteArray dbMask = rsa_mgf1(seed, nLen - hLen - 1, key.padding_.hask_hash_mode);

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

std::vector<uint8_t> rsa_encrypt(RsaKey &key, std::span<const uint8_t> src)
{
    if (key.padding_.mode == RsaPadding::OAEP)
    {
        // TODO: Storing so that we can later log this for creating tests
        ByteArray seed;
        return rsa_encrypt_primative(key, rsa_oaep_encode(key, src));
    }
    else
    {
        return rsa_encrypt_primative(key, src);
    }
}

std::vector<uint8_t> rsa_decrypt(RsaKey &key, std::span<const uint8_t> cipher)
{
    if (key.padding_.mode == RsaPadding::OAEP)
    {
        ByteArray EM = rsa_decrypt_primative(key, cipher);
        return rsa_oaep_decode(key, EM);
    }
    else
    {
        return rsa_decrypt_primative(key, cipher);
    }
}

RsaCrtParams::RsaCrtParams()
{
    dp_ = BN_secure_new(),
    dq_ = BN_secure_new(),
    qinv_ = BN_secure_new(),
    p_ = BN_secure_new(),
    q_ = BN_secure_new();
    enabled_ = false;
}

RsaCrtParams::~RsaCrtParams()
{
    BN_clear_free(dp_);
    BN_clear_free(qinv_);
    BN_clear_free(dq_);
    BN_clear_free(p_);
    BN_clear_free(q_);
}

RsaKey::~RsaKey()
{
    BN_clear_free(d_);
    BN_clear_free(e_);
    BN_clear_free(n_);
}

RsaKey::RsaKey()
{
    modulus_bits_ = 4096;
    n_ = BN_secure_new(),
    e_ = BN_secure_new(),
    d_ = BN_secure_new();
    padding_.mode = RsaPadding::NONE;
}

void RsaKey::reset_padding()
{
    padding_.mode = RsaPadding::NONE;
    padding_.label_hash_mode = DIGEST_MODE::NONE;
    padding_.hask_hash_mode = DIGEST_MODE::NONE;
    padding_.label.clear();
    padding_.seed.clear();
}
