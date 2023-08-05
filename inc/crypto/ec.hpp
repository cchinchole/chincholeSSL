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

int FIPS_186_4_B_4_2_KeyPairGeneration( cECKey *ret );
int FIPS_186_5_6_4_1_GenerateSignature(cECSignature *sig, char *msg, cECKey *key, char *KSecret = NULL);
int FIPS_186_5_6_4_2_VerifySignature( cECSignature *sig, char *msg, cECPrimeField *D, cECPoint *Q );
int ec_sign_message_and_test(cECSignature *sig, cECKey *key, char *msg);
