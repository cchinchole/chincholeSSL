#include "internal/ec.hpp"
#include "inc/utils/bytes.hpp"
#include "inc/hash/hash.hpp"

#include <cstddef>
#include <math.h>
#include <openssl/bn.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>

/* SP 800-186: Domain parameters source */
/* Easily access: https://neuromancer.sk/std/nist/ */
void ec_copy_point(EcPoint *to, EcPoint *from);
void ec_double(EcPrimeField *g, EcPoint *final_ret, EcPoint *a, BN_CTX *ctx = BN_CTX_new());
void ec_add(EcPrimeField *g, EcPoint *final_out, EcPoint *a, EcPoint *b, BN_CTX *ctx = BN_CTX_new());
void ec_scalar_mult(EcPrimeField *g, EcPoint *Q_output, BIGNUM *scalar, EcPoint *Point, BN_CTX *ctx = NULL);

// FIPS 186-4 B.4.2
int ec_generate_keypair(EcKey &ret)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    EcKey key(ret.group_);
    EcPrimeField *group = key.getGroup();
    BIGNUM *tmp = BN_dup(group->n_);
    BN_sub(tmp, tmp, BN_value_one());

Generate:
    BN_priv_rand_range_ex(key.priv_, tmp, 0, ctx);

    if (BN_cmp(key.priv_, tmp) == 1)
    {
        goto Generate;
    }

    ec_scalar_mult(group, &key.pub_, key.priv_, group->g_);
    ret = key;
    if (tmp)
        BN_clear_free(tmp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

/* FIPS 186-5 6.4.1 */
int ec_generate_signature(EcKey &key, cEcSignature &sig,
                                       ByteSpan msg,
                                       cssl::DIGEST_MODE shaMode,
                                       char *kSecret)
{
    int retcode = -1;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *k_secret = BN_CTX_get(ctx);
    BIGNUM *k_secret_inv = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *e = BN_CTX_get(ctx);
    EcPrimeField *group = key.getGroup();
    EcPoint *return_point = new EcPoint();

    // Step 1 - 2
    auto hash = cssl::Hasher::hash(msg, shaMode);
    int len_modulus = BN_num_bits(group->n_); /* N = len(n) */
    int len_hash = hash.size() * 8;
    BN_bin2bn(hash.data(), hash.size(), tmp);
    hash.clear();
    if (len_hash > len_modulus)
        BN_rshift(e, tmp, len_hash - len_modulus);
    else
        BN_copy(e, tmp);

    // Step 3 - 4
    // Add in forcing a KSecret for utilization with test suite
    if (!kSecret)
    {
        BN_rand_range_ex(k_secret, group->n_, 0, ctx);
    }
    else
    {
        BN_hex2bn(&k_secret, kSecret);
    }
    BN_mod_inverse(k_secret_inv, k_secret, group->n_, ctx);

    /* Step 5 */
    ec_scalar_mult(group, return_point, k_secret, group->g_);

    /* Step 6 - 8 */
    BN_mod(sig.r_, return_point->x_, group->n_, ctx);

    /* Step 9 */
    BN_mul(tmp, sig.r_, key.priv_, ctx);
    BN_add(tmp, tmp, e);
    BN_mod_mul(sig.s_, k_secret_inv, tmp, group->n_, ctx);

    /* Step 10 */
    BN_zero(k_secret);
    BN_zero(k_secret_inv);

    /* Step 11 */
    if (BN_is_zero(sig.s_) || BN_is_zero(sig.r_))
    {
        retcode = -1;
        goto ending;
    }
    retcode = 0;
ending:
    delete return_point;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retcode;
}

/* FIPS 186-5 6.4.2 */
int ec_verify_signature(EcKey &key, cEcSignature &sig,
                                     ByteSpan msg,
                                     cssl::DIGEST_MODE shaMode)
{
    int retcode = -1;
    EcPrimeField *d_group = key.getGroup();
    EcPoint *q_pub = &key.pub_;

    BN_CTX *ctx = BN_CTX_secure_new();
    BN_CTX_start(ctx);

    BIGNUM *sinv = BN_CTX_get(ctx);
    BIGNUM *e = BN_CTX_get(ctx);
    BIGNUM *u = BN_CTX_get(ctx);
    BIGNUM *u2 = BN_CTX_get(ctx);
    BIGNUM *v = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    EcPoint *addend1 = new EcPoint();
    EcPoint *addend2 = new EcPoint();
    EcPoint *return_point = new EcPoint();

    // Step 2 - 3: Hash the message
    ByteArray hash = cssl::Hasher::hash(msg, shaMode);

    if (BN_is_zero(sig.r_) || BN_is_zero(sig.s_) || BN_ucmp(sig.r_, d_group->n_) >= 0 ||
        BN_ucmp(sig.s_, d_group->n_) >= 0)
        return -1; // Either R or S is not within 0, n-1

    // Step 3: Convert leftmost N bits of hash to integer
    int len_modulus = BN_num_bits(d_group->n_); // N = len(n)
    int len_hash = hash.size() * 8; // hash length in bits

    // Store hash in tmp
    BN_bin2bn(hash.data(), hash.size(), tmp);

    // If the Hash bits > Order bits then only copy the higher order bits to E
    //  else fully copy the hash into E
    if (len_hash > len_modulus)
        BN_rshift(e, tmp, len_hash - len_modulus);
    else
        BN_copy(e, tmp);

    // Step 4: Compute s⁻¹ mod n
    BN_mod_inverse(sinv, sig.s_, d_group->n_, ctx);

    // Step 5: Compute u = e⋅s⁻¹ mod n, v = r⋅s⁻¹ mod n 
    BN_mod_mul(u, e, sinv, d_group->n_, ctx);
    BN_mod_mul(v, sig.r_, sinv, d_group->n_, ctx);

    ec_scalar_mult(d_group, addend1, u, d_group->g_);
    ec_scalar_mult(d_group, addend2, v, q_pub);
    ec_add(d_group, return_point, addend1, addend2);

    if (return_point->isAtInfinity())
    {
        retcode = -1;
        goto ending;
    }

    BN_nnmod(tmp, return_point->x_, d_group->n_, ctx);

    if (BN_cmp(sig.r_, tmp) == 0)
    {
        retcode = 0;
        goto ending;
    }
    else
    {
        retcode = -1;
        goto ending;
    }

ending:
    delete addend1;
    delete addend2;
    delete return_point;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retcode;
}

EcPoint::EcPoint()
{
    x_ = BN_secure_new();
    y_ = BN_secure_new();
}

cEcSignature::cEcSignature()
{
    r_ = BN_new();
    s_ = BN_new();
}

EcKey::EcKey(cssl::EC_GROUP group)
{
    this->group_ = group;
    this->priv_ = BN_secure_new();
}

bool EcPoint::isAtInfinity()
{
    return (BN_is_zero(this->x_) && BN_is_zero(this->y_));
}

void EcPoint::setInfinity()
{
    BN_zero(this->x_);
    BN_zero(this->y_);
}

void ec_copy_point(EcPoint *to, EcPoint *from)
{
    BN_copy(to->x_, from->x_);
    BN_copy(to->y_, from->y_);
}

void ec_double(EcPrimeField *g,
              EcPoint *final_ret,
              EcPoint *a,
              BN_CTX *ctx)
{
    BN_CTX_start(ctx);

    // Our return point so we do not mess with the final point until we are
    // finished
    EcPoint *ret = new EcPoint();
    ec_copy_point(ret, a);

    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *tmp3 = BN_CTX_get(ctx);
    BIGNUM *x3 = BN_CTX_get(ctx);
    BIGNUM *x2 = BN_CTX_get(ctx);
    BIGNUM *y2 = BN_CTX_get(ctx);
    BIGNUM *zero = BN_CTX_get(ctx);
    BN_set_word(zero, 0);

    BN_copy(x3, ret->x_);
    BN_copy(x2, ret->x_);
    BN_copy(y2, ret->y_);

    BN_mul_word(x3, 3);
    BN_mul_word(x2, 2);
    BN_mul_word(y2, 2);

    // (3x * x + Acurve) * modinv( 2y, Pcurve ) % Pcurve 
    BN_mul(tmp, x3, ret->x_, ctx);
    BN_add(tmp, tmp, g->a_);              // tmp holds 3x^2+Acurve  
    BN_mod_inverse(tmp2, y2, g->p_, ctx); // tmp2 holds 2y^-1 mod( pCurve )
    BN_mod(tmp2, tmp2, g->p_, ctx);
    BN_mul(tmp, tmp, tmp2, ctx); // tmp now holds lambda 
    BN_mul(tmp2, tmp, tmp, ctx); // tmp2 now holds lambda^2 
    BN_sub(tmp3, tmp2, x2);
    BN_mod(ret->x_, tmp3, g->p_, ctx);

    BN_sub(tmp2, a->x_, ret->x_);  // tmp2 now holds X - ret.x 
    BN_mul(tmp, tmp, tmp2, ctx); // tmp now holds lambda * (X - ret.x) 
    BN_sub(tmp, tmp, a->y_);      // tmp now holds lambda * (X - ret.x) - Y 
    BN_mod(ret->y_, tmp, g->p_,
           ctx); // ret->y now holds ( lambda * (X - ret.x) - Y ) mod P 

    if (BN_cmp(ret->x_, zero) == -1)
        BN_add(ret->x_, ret->x_, g->p_);

    if (BN_cmp(ret->y_, zero) == -1)
        BN_add(ret->y_, ret->y_, g->p_);
    ec_copy_point(final_ret, ret);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    delete ret;
}

void ec_add(EcPrimeField *g,
           EcPoint *final_out,
           EcPoint *a,
           EcPoint *b,
           BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    EcPoint *res = new EcPoint();
    BIGNUM *lambda = BN_CTX_get(ctx);
    BIGNUM *tmpAddSub = BN_CTX_get(ctx);
    BIGNUM *tmpInv = BN_CTX_get(ctx);
    BIGNUM *tmpMul = BN_CTX_get(ctx);
    BIGNUM *zero = BN_CTX_get(ctx);
    BN_set_word(zero, 0);
    if (a->isAtInfinity() && b->isAtInfinity())
    {
        res->setInfinity();
        goto ending;
    }
    else if (a->isAtInfinity())
    {
        ec_copy_point(res, b);
        goto ending;
    }
    else if (b->isAtInfinity())
    {
        ec_copy_point(res, a);
        goto ending;
    }
    else if (!BN_cmp((a->x_), (b->x_)) && !BN_cmp((a->y_), (b->y_)))
    {
        BN_mod(tmp, a->y_, (g->p_), ctx);
        if (BN_is_zero(tmp))
        {
            res->setInfinity();
            goto ending;
        }
        ec_double(g, res, a);
        goto ending;
    }
    else
    {
        BN_sub(tmp, b->x_, a->x_);
        BN_mod(tmp, tmp, g->p_, ctx);
        if (BN_is_zero(tmp))
        {
            res->setInfinity();
            goto ending;
        }

        BN_sub(tmpAddSub, b->x_, a->x_);
        BN_mod_inverse(tmpInv, tmpAddSub, g->p_, ctx);
        BN_sub(tmpAddSub, b->y_, a->y_);
        BN_mul(lambda, tmpAddSub, tmpInv, ctx);

        BN_mul(tmpMul, lambda, lambda, ctx);
        BN_add(tmpAddSub, a->x_, b->x_);
        BN_sub(tmpAddSub, tmpMul, tmpAddSub);
        BN_mod(res->x_, tmpAddSub, g->p_, ctx);

        BN_sub(tmpAddSub, a->x_, res->x_);
        BN_mul(tmpMul, lambda, tmpAddSub, ctx);
        BN_sub(tmpAddSub, tmpMul, a->y_);
        BN_mod(res->y_, tmpAddSub, g->p_, ctx);

        if (BN_cmp(res->x_, zero) == -1)
            BN_add(res->x_, res->x_, g->p_);

        if (BN_cmp(res->y_, zero) == -1)
            BN_add(res->y_, res->y_, g->p_);

        goto ending;
    }
ending:
    ec_copy_point(final_out, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    delete res;
}

void ec_scalar_mult(EcPrimeField *g, EcPoint *Q_output, BIGNUM *scalar, EcPoint *Point, BN_CTX *ctx) {
    if (!g || !Q_output || !scalar || !Point) {
        throw std::invalid_argument("Null pointer provided");
    }
    bool providedCtx = true;

    // Initialize context and temporary variables
    if(ctx == NULL)
    {
        ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        providedCtx = false;
    }
    EcPoint *result = new EcPoint();
    result->setInfinity(); // Initialize result as point at infinity

    // Precomputation table (window size 4, so 2^4 = 16 points)
    const int window_size = 4;
    const int table_size = 1 << window_size; // 16
    EcPoint *table[table_size];
    for (int i = 0; i < table_size; i++) {
        table[i] = new EcPoint();
        table[i]->setInfinity();
    }

    // Set table[1] = Point
    ec_copy_point(table[1], Point);

    // Precompute multiples: table[i] = i * Point
    for (int i = 2; i < table_size; i++) {
        if (i % 2 == 0) {
            // table[i] = 2 * table[i/2]
            ec_double(g, table[i], table[i/2]);
        } else {
            // table[i] = table[i-1] + table[1]
            ec_add(g, table[i], table[i-1], table[1]);
        }
    }

    // Process scalar in windows
    int bits = BN_num_bits(scalar);
    int windows = (bits + window_size - 1) / window_size;

    for (int i = windows - 1; i >= 0; i--) {
        // Perform 4 point doublings
        for (int j = 0; j < window_size; j++) {
            EcPoint *temp = new EcPoint();
            ec_double(g, temp, result);
            ec_copy_point(result, temp);
            delete temp;
        }

        // Extract window bits
        int wvalue = 0;
        for (int j = window_size - 1; j >= 0; j--) {
            int bit = BN_is_bit_set(scalar, i * window_size + j);
            wvalue = (wvalue << 1) | bit;
        }

        // Add precomputed point if wvalue > 0
        if (wvalue > 0 && !table[wvalue]->isAtInfinity()) {
            EcPoint *temp = new EcPoint();
            ec_add(g, temp, result, table[wvalue]);
            ec_copy_point(result, temp);
            delete temp;
        }
    }

    // Copy result to output
    ec_copy_point(Q_output, result);

    // Clean up
    for (int i = 0; i < table_size; i++) {
        delete table[i];
    }
    delete result;
    if(!providedCtx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
}

/*
 * Original ECScalarMult, less optimal than the new method which uses window.
void ECScalarMult(cECPrimeField *g,
                  cECPoint *Q_output,
                  BIGNUM *scalar,
                  cECPoint *Point,
                  BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    int i = 0;
    cECPoint *temp = new cECPoint();
    cECPoint *PointCopy = new cECPoint();
    cECPoint *QRes = new cECPoint();
    ECCopyPoint(PointCopy, Point);
    QRes->setInfinity();
    for (i = BN_num_bits(scalar); i >= 0; i--)
    {
        if (BN_is_bit_set(scalar, i))
            break;
    }

    for (int j = 0; j <= i; j++)
    {
        if (BN_is_bit_set(scalar, j))
        {
            ECadd(g, temp, QRes, PointCopy);
            ECCopyPoint(QRes, temp);
        }
        ECdouble(g, temp, PointCopy);
        ECCopyPoint(PointCopy, temp);
    }
    ECCopyPoint(Q_output, QRes);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    delete temp;
    delete PointCopy;
    delete QRes;
}
*/

std::string ec_group_string(cssl::EC_GROUP group)
{
    switch (group)
    {
        case cssl::EC_GROUP::P224:
        return "P-224";
        break;
        case cssl::EC_GROUP::P256:
        return "P-256";
        break;
        case cssl::EC_GROUP::P384:
        return "P-384";
        break;
        case cssl::EC_GROUP::P521:
        return "P-521";
        break;
    default:
        return "";
        break;
    }
    return "";
}

class CurveRegistry
{
  private:
    static std::map<std::string, std::shared_ptr<EcPrimeField>> curves;

  public:
    static std::shared_ptr<EcPrimeField> GetCurve(const std::string &curveName)
    {
        auto it = curves.find(curveName);
        if (it == curves.end())
        {
            if (curveName == "P-224")
            {
                curves[curveName] = std::make_shared<EcPrimeField>(
                    "ffffffffffffffffffffffffffffffff000000000000000000000001",
                    "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
                    "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
                    "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
                    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
                    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
                    cssl::EC_GROUP::P224);
            }
            else if (curveName == "P-256")
            {
                curves[curveName] = std::make_shared<EcPrimeField>(
                    "ffffffff00000001000000000000000000000000ffffffffffffffffff"
                    "ffffff",
                    "ffffffff00000001000000000000000000000000ffffffffffffffffff"
                    "fffffc",
                    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27"
                    "d2604b",
                    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc"
                    "632551",
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d8"
                    "98c296",
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837"
                    "bf51f5",
                    cssl::EC_GROUP::P256);
            }
            else if (curveName == "P-521")
            {
                curves[curveName] = std::make_shared<EcPrimeField>(
                    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffff",
                    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffffffffffffc",
                    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489"
                    "918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1"
                    "ef451fd46b503f00",
                    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47ae"
                    "bb6fb71e91386409",
                    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af"
                    "606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429b"
                    "f97e7e31c2e5bd66",
                    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd"
                    "17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c240"
                    "88be94769fd16650",
                    cssl::EC_GROUP::P521);
            }
            else if (curveName == "P-384")
            {
                curves[curveName] = std::make_shared<EcPrimeField>(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffeffffffff0000000000000000ffffffff",
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffeffffffff0000000000000000fffffffc",
                    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f50"
                    "13875ac656398d8a2ed19d2a85c8edd3ec2aef",
                    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4"
                    "372ddf581a0db248b0a77aecec196accc52973",
                    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082"
                    "542a385502f25dbf55296c3a545e3872760ab7",
                    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5"
                    "f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                    cssl::EC_GROUP::P384);
            }
            else
            {
                throw std::runtime_error("Unknown curve: " + curveName);
            }
        }
        return curves[curveName];
    }
};
std::map<std::string, std::shared_ptr<EcPrimeField>> CurveRegistry::curves;

EcPrimeField *EcKey::getGroup()
{
    return CurveRegistry::GetCurve(ec_group_string(this->group_)).get();
}
