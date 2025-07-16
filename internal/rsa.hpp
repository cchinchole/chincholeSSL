#include "../inc/hash/hash.hpp"
#include "../inc/utils/bytes.hpp"
#include <cstdint>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <vector>

enum class RSA_Padding{
    OAEP,
    NONE
};

class RSA_Padding_Params {
public:
    RSA_Padding mode;
    DIGEST_MODE hashMode;
    DIGEST_MODE maskHashMode;
    ByteArray label;
    ByteArray seed;
};

class RSA_CRT_Params {
public:
    BIGNUM *dp, *dq, *qInv, *p, *q;
    bool enabled = false;
    RSA_CRT_Params();
    ~RSA_CRT_Params();
};

class cRSAKey {
public:
    /* Need the N, E, D */
    /* (N, E) Form the public */
    /* (N, D) Form the private */
    int kBits = 4096; 
    BIGNUM *n, *e, *d;
    RSA_CRT_Params crt;
    RSA_Padding_Params padding;
    void reset();
    cRSAKey();
   ~cRSAKey();
};
int rsa_sp800_56b_pairwise_test(cRSAKey &key);
int gen_rsa_sp800_56b(cRSAKey &key, bool constTime);
void RSA_GenerateKey(cRSAKey &key, int kBits);
void RSA_AddOAEP(cRSAKey &key, ByteSpan label, ByteSpan seed, DIGEST_MODE hashMode, DIGEST_MODE maskHashMode);
void RSA_AddOAEP(cRSAKey &key, ByteSpan label, DIGEST_MODE hashMode, DIGEST_MODE maskHashMode);
ByteArray RSA_Encrypt(cRSAKey &key, std::span<const uint8_t> src);
ByteArray RSA_Decrypt(cRSAKey &key, std::span<const uint8_t> cipher);
ByteArray mgf1(std::span<const uint8_t> seed, size_t maskLen, DIGEST_MODE shaMode = DIGEST_MODE::SHA_1);
/*
 * Key Pair:
 * <d, n>: Form the private decryption key.
 * <e, n>: Form the public encryption key.
 *
 * Chinese Remainder Theorem Params:
 * <p, q, dP, dQ, qInv>: Form the quintuple private key used for decryption.
 * CRT and Euler's Theorem are used here.
 * https://www.di-mgt.com.au/crt_rsa.html
 * https://math.berkeley.edu/~charles/55/2-21.pdf
 * Benefit of using RSA-CRT over RSA is to speed up the decryption time.
 */

/*
 * https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural
 * :: Why there are leading ones in rng generation
 * https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html :: CRT
 * https://mathstats.uncg.edu/sites/pauli/112/HTML/seceratosthenes.html :: Sieve
 * of Eratosthenes
 * http://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html
 * :: RSA https://www.di-mgt.com.au/crt_rsa.html :: CRT encryption
 * https://security.stackexchange.com/questions/176394/how-does-openssl-generate-a-big-prime-number-so-fast
 * :: OpenSSL Generating prime numbers
 */
