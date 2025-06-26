#ifndef ECDH_HPP
#define ECDH_HPP
#include <string>
#include <memory>
#include <openssl/bn.h>
#include <vector>
#include "../hash/sha.hpp"

enum ECGroup
{
    P224,
    P256,
    P384,
    P521,
    NA
};

class cECPoint
{
public:
    BIGNUM *x, *y;
    cECPoint();
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
    std::shared_ptr<cECPrimeField> group;
    BIGNUM *priv; /* d */
    cECPoint *pub; /* Q */
    cECKey();
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

//void ECCopyGroup(cECPrimeField *to, cECPrimeField *from);
//int FIPS_186_4_B_4_2_KeyPairGeneration(cECKey *ret, std::string group);
//int FIPS_186_5_6_4_1_GenerateSignature(cECSignature *sig, uint8_t *msg, size_t msg_len, cECKey *key, SHA_MODE shaMode = SHA_512, char *KSecret = NULL);
//int FIPS_186_5_6_4_2_VerifySignature(cECSignature *sig, uint8_t *msg, size_t msg_len, cECPrimeField *D, cECPoint *Q, SHA_MODE shaMode = SHA_512);
std::string ECGroupString(ECGroup group);
void EC_SetGroup(cECKey *key, ECGroup group);
int EC_GenerateSignature(cECKey *key, cECSignature *sig, std::vector<uint8_t>msg, SHA_MODE shaMode);
int EC_VerifySignature(cECKey *key, cECSignature *sig, std::vector<uint8_t>msg, SHA_MODE shaMode);
int EC_Generate_KeyPair(cECKey *key, ECGroup group);

#endif
