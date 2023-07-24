#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <vector>
#include <iostream>


struct RSA_Params {
  BIGNUM *p, *q, *e, *n, *d, *dp, *dq, *qInv;
};

int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx = BN_CTX_secure_new(), bool constTime = true);
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx = BN_CTX_secure_new());
int rsa_roundtrip(std::string msg, RSA_Params* rsa);
int printParameter(std::string param_name, BIGNUM* num);


class cRSAKey {
private:
int kBits;
public:
RSA_Params* params;
cRSAKey(int bits, BIGNUM *eGiven, bool auxMode = true, BN_CTX* ctx = BN_CTX_secure_new());
unsigned char* encrypt(unsigned int *out_len, char *src, BN_CTX *ctx = BN_CTX_secure_new());
std::string decrypt(unsigned char *cipher, unsigned int cipher_length, BN_CTX *ctx = BN_CTX_secure_new(), bool crt = true);
};

int roundTrip(cRSAKey* rsa, char* str);