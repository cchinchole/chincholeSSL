#include <openssl/bn.h>

class cECPoint {
    public:
    BIGNUM *x = BN_secure_new(), *y = BN_secure_new();
};

class cECPrimeField {
    public:
    BIGNUM *p = BN_secure_new(), *a = BN_secure_new(), *b = BN_secure_new(), *n = BN_secure_new();
    int h;
    cECPoint *G = new cECPoint();
};

class Prime256v1 : public cECPrimeField {
    public:
    Prime256v1();
};



class PrimeTestField : public cECPrimeField {
    public:
    PrimeTestField();
};

class cECKey {
    public:
    cECPrimeField *group;
    BIGNUM *priv = BN_new() /* d */;
    cECPoint *pub = new cECPoint(); /* Q */;
};

class cECSignature {
    public:
        BIGNUM *R;
        BIGNUM *S;
    cECSignature();
};

int ec_generate_key( cECKey *ret );
int ec_generate_signature(cECSignature *sig, char *msg, cECKey *key, char *KSecret = NULL);
int ec_sign_message(cECSignature *sig, cECKey *key, char *msg);