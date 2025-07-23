#pragma once
#include "../inc/utils/bytes.hpp"
#include "../inc/types.hpp"
#include <openssl/bn.h>
#include <string>

std::string ec_group_string(cssl::EC_GROUP group);

// Purely internal classes, no reason to export them.
class EcPoint {
  public:
    BIGNUM* x_;
    BIGNUM* y_;
    EcPoint();
    EcPoint& operator=(const EcPoint& other) {
        if (this != &other) {
            BN_copy(x_, other.x_);
            BN_copy(y_, other.y_);
        }
        return *this;
    }
    ~EcPoint() {
        BN_free(x_);
        BN_free(y_);
    }
    bool isAtInfinity();
    void setInfinity();
};

class EcPrimeField {
  public:
    BIGNUM* p_;
    BIGNUM* a_;
    BIGNUM* b_;
    BIGNUM* n_;
    int h;
    EcPoint *g_;
    cssl::EC_GROUP group_;
    EcPrimeField(const char* p, const char* a, const char* b, const char* n, const char* gx, const char* gy, cssl::EC_GROUP group) {
        p_ = BN_secure_new();
        a_ = BN_secure_new();
        b_ = BN_secure_new();
        n_ = BN_secure_new();
        group_ = group;
        g_ = new EcPoint();
        BN_hex2bn(&p_, p);
        BN_hex2bn(&a_, a);
        BN_hex2bn(&b_, b);
        BN_hex2bn(&n_, n);
        BN_hex2bn(&(g_->x_), gx);
        BN_hex2bn(&(g_->y_), gy);
    }
    virtual ~EcPrimeField() {
        BN_free(p_);
        BN_free(a_);
        BN_free(b_);
        BN_free(n_);
        delete g_;
    }
};

class EcKey {
  public:
    cssl::EC_GROUP group_;
    BIGNUM* priv_; /* d */
    EcPoint pub_; /* Q */
    EcKey(cssl::EC_GROUP group);
    EcKey& operator=(const EcKey& from) {
        if (this != &from) {
            BN_copy(priv_, from.priv_);
            group_ = from.group_;
            pub_ = from.pub_;
        }
        return *this;
    }
    EcPrimeField* getGroup();
    ~EcKey() { BN_free(priv_); }
};

class cEcSignature {
  public:
    BIGNUM* r_;
    BIGNUM* s_;
    cEcSignature();
    ~cEcSignature() {
        BN_free(r_);
        BN_free(s_);
    }
};


int ec_generate_keypair(EcKey &ret);
int ec_verify_signature(EcKey &key, cEcSignature &sig, ByteSpan msg,
                       cssl::DIGEST_MODE shaMode = cssl::DIGEST_MODE::SHA_512);
int ec_generate_signature(EcKey &key, cEcSignature &sig,
                                       ByteSpan msg,
                                       cssl::DIGEST_MODE shaMode = cssl::DIGEST_MODE::SHA_512,
                                       char *kSecret = NULL);
