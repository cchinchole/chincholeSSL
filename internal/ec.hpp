#ifndef ECDH_HPP
#define ECDH_HPP
#include "../inc/types.hpp"
#include "../inc/hash/hash.hpp"
#include "../inc/utils/bytes.hpp"
#include <openssl/bn.h>
#include <string>

std::string ECGroupString(ECGroup group);

// Purely internal classes, no reason to export them.
class cECPoint {
  public:
    BIGNUM *x, *y;
    cECPoint();
    cECPoint &operator=(const cECPoint &other) {
        if (this != &other) {
            BN_copy(x, other.x);
            BN_copy(y, other.y);
        }
        return *this;
    }
    ~cECPoint() {
        BN_free(x);
        BN_free(y);
    }
    bool isAtInfinity();
    void setInfinity();
};

class cECPrimeField {
  public:
    BIGNUM *p, *a, *b, *n;
    int h;
    cECPoint *G;
    ECGroup group;
    cECPrimeField(const char *p, const char *a,const char *b,const char *n,const  char *gx,const  char *gy, ECGroup group) {
        this->p = BN_secure_new();
        this->a = BN_secure_new();
        this->b = BN_secure_new();
        this->n = BN_secure_new();
        this->group = group;
        G = new cECPoint();
        BN_hex2bn(&this->p, p);
        BN_hex2bn(&this->a, a);
        BN_hex2bn(&this->b, b);
        BN_hex2bn(&this->n, n);
        BN_hex2bn(&(this->G->x), gx);
        BN_hex2bn(&(this->G->y), gy);
    }
    virtual ~cECPrimeField() {
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(n);
        delete G;
    }
};

class cECKey {
  public:
    ECGroup group;
    BIGNUM *priv; /* d */
    cECPoint pub; /* Q */
    cECKey(ECGroup group);
    cECKey &operator=(const cECKey &from) {
        if (this != &from) {
            BN_copy(this->priv, from.priv);
            this->group = from.group;
            this->pub = from.pub;
        }
        return *this;
    }
    cECPrimeField *getGroup();
    ~cECKey() { BN_free(priv); }
};

class cECSignature {
  public:
    BIGNUM *R;
    BIGNUM *S;
    cECSignature();
    ~cECSignature() {
        BN_free(R);
        BN_free(S);
    }
};


int EC_GenerateKeyPair(cECKey &ret);
int EC_VerifySignature(cECKey &key, cECSignature &sig, std::span<const uint8_t> msg,
                       DIGEST_MODE shaMode = DIGEST_MODE::SHA_512);

int EC_GenerateSignature(cECKey &key, cECSignature &sig,
                                       std::span<const uint8_t> msg,
                                       DIGEST_MODE shaMode = DIGEST_MODE::SHA_512,
                                       char *KSecret = NULL);

#endif
