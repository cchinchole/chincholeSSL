#include "../hash/hash.hpp"
#include "../utils/bytes.hpp"
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
};

class RSA_CRT_Params {
public:
    BIGNUM *dp, *dq, *qInv, *p, *q;
    bool enabled;
    RSA_CRT_Params();
    ~RSA_CRT_Params();
};

class cRSAKey {
public:
    /* Need the N, E, D */
    /* (N, E) Form the public */
    /* (N, D) Form the private */
    int kBits = 4096; 
    //BIGNUM *N = BN_secure_new(), *E = BN_secure_new(), *D = BN_secure_new();
    BIGNUM *n, *e, *d;
    RSA_CRT_Params crt;
    RSA_Padding_Params padding;
    cRSAKey();
   ~cRSAKey();
};

void RSA_SetPaddingMode(cRSAKey &key, RSA_Padding padding_mode, ByteArray label = {}, DIGEST_MODE hashMode = DIGEST_MODE::NONE, DIGEST_MODE maskHashMode = DIGEST_MODE::NONE);
void RSA_GenerateKey(cRSAKey &key, int kBits=4096, std::string N="", std::string E="",
                     std::string D="", std::string ex1="", std::string ex2="",
                     std::string coef="", std::string P="", std::string Q="");
//void RSA_GenerateKey(cRSAKey &key, BIGNUM *e = nullptr, int kBits = 4096, bool auxMode = true);
//void RSA_GenerateKey(cRSAKey &key, int kBits, std::string e,  std::string p1, std::string p2);
std::vector<uint8_t> RSA_Encrypt_Primative(cRSAKey &key, const std::vector<uint8_t> &src);
std::vector<uint8_t> RSA_Encrypt(cRSAKey &key, const std::vector<uint8_t> &src);
std::vector<uint8_t> RSA_Decrypt(cRSAKey &key, const std::vector<uint8_t> &cipher);
std::vector<uint8_t> mgf1(const std::vector<uint8_t> &seed, size_t maskLen, DIGEST_MODE shaMode = DIGEST_MODE::SHA_256);
ByteArray OAEP_Encode(cRSAKey &key, const ByteArray &msg, ByteArray &seed, bool givenSeed);
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
