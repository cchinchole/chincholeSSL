

enum cECGroup {
    PRIME192
};

class cECPoint {

};

class cECKey {
    public:
    cECGroup *group = new cECGroup();
    cECPoint *g = new cECPoint();
    BIGNUM *order = BN_new();
    BIGNUM *priv = BN_new(), *pub = BN_new();
};

int ec_generate_key(  );