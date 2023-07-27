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
    Prime256v1()
    {
        char *p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        char *a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        char *b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        char *Gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        char *Gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        char *n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

        BN_hex2bn(&this->p, p);
        BN_hex2bn(&this->a, a);
        BN_hex2bn(&this->b, b);
        BN_hex2bn(&this->n, n);
        BN_hex2bn(&(this->G->x), Gx);
        BN_hex2bn(&(this->G->y), Gy);
    }
};

class PrimeTestField : public cECPrimeField {
    public:
    PrimeTestField()
    {
        char *p = "11";
        char *a = "1";
        char *b = "7";
        char *Gx = "1";
        char *Gy = "3";
        char *n = "0";

        BN_hex2bn(&this->p, p);
        BN_hex2bn(&this->a, a);
        BN_hex2bn(&this->b, b);
        BN_hex2bn(&this->n, n);
        BN_hex2bn(&(this->G->x), Gx);
        BN_hex2bn(&(this->G->y), Gy);
    }
};



class cECKey {
    public:
    cECPrimeField *group;
    BIGNUM *priv = BN_new() /* d */;
    cECPoint *pub = new cECPoint(); /* Q */;
};

int ec_generate_key(  );