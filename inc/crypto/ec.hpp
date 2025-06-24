#ifndef ECDH_HPP
#define ECDH_HPP
#include <openssl/bn.h>
#include "../hash/sha.hpp"

class cECPoint
{
public:
    BIGNUM *x = BN_secure_new(), *y = BN_secure_new();
     ~cECPoint();
};

class cECPrimeField
{
public:
    BIGNUM *p = BN_secure_new(), *a = BN_secure_new(), *b = BN_secure_new(), *n = BN_secure_new();
    int h;
    cECPoint *G = new cECPoint();
    virtual ~cECPrimeField();
};

class Prime224 : public cECPrimeField
{
public:
    Prime224();
};

class Prime256v1 : public cECPrimeField
{
public:
    Prime256v1();
};

class Prime384 : public cECPrimeField
{
public:
    Prime384();
};

class Prime521 : public cECPrimeField
{
public:
    Prime521();
};

class cECKey
{
public:
    cECPrimeField *group;
    BIGNUM *priv = BN_secure_new(); /* d */
    cECPoint *pub = new cECPoint(); /* Q */
    ~cECKey();
};

class cECSignature
{
public:
    BIGNUM *R;
    BIGNUM *S;
    cECSignature();
     ~cECSignature();
};

int FIPS_186_4_B_4_2_KeyPairGeneration(cECKey *ret);
int FIPS_186_5_6_4_1_GenerateSignature(cECSignature *sig, char *msg, size_t msg_len, cECKey *key, SHA_MODE shaMode = SHA_512, char *KSecret = NULL);
int FIPS_186_5_6_4_2_VerifySignature(cECSignature *sig, char *msg, size_t msg_len, cECPrimeField *D, cECPoint *Q, SHA_MODE shaMode = SHA_512);
int ec_sign_message_and_test(cECSignature *sig, cECKey *key, char *msg);
#endif
