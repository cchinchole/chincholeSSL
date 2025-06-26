#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <vector>

/*
struct RSA_Params {
  BIGNUM *p, *q, *e, *n, *d, *dp, *dq, *qInv;
};
*/

class RSA_CRT_Params {
public:
    BIGNUM *dp, *dq, *qInv, *p, *q;
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
    RSA_CRT_Params *crt;
    cRSAKey();
   ~cRSAKey();
};

void RSA_GenerateKey(cRSAKey *key, BIGNUM *e = nullptr, int kBits = 4096, bool auxMode = true);
std::vector<uint8_t> RSA_Encrypt(cRSAKey *key, const std::vector<uint8_t> &src);
std::vector<uint8_t> RSA_Decrypt(cRSAKey *key, const std::vector<uint8_t> &cipher, bool crt = true);
