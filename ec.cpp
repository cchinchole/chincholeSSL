#include "inc/crypto/ec.hpp"

#include <linux/random.h>
#include <math.h>
#include <openssl/bn.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>

#include "inc/math/primes.hpp"

/* SP 800-186: Domain parameters source */
/* Easily access: https://neuromancer.sk/std/nist/ */
class CurveRegistry
{
  private:
    static std::map<std::string, std::shared_ptr<cECPrimeField>> curves;

  public:
    static std::shared_ptr<cECPrimeField> GetCurve(const std::string &curveName)
    {
        auto it = curves.find(curveName);
        if (it == curves.end())
        {
            if (curveName == "P-224")
            {
                curves[curveName] = std::make_shared<cECPrimeField>(
                    "ffffffffffffffffffffffffffffffff000000000000000000000001",
                    "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
                    "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
                    "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
                    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
                    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
                    ECGroup::P224);
            }
            else if (curveName == "P-256")
            {
                curves[curveName] = std::make_shared<cECPrimeField>(
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
                    ECGroup::P256);
            }
            else if (curveName == "P-521")
            {
                curves[curveName] = std::make_shared<cECPrimeField>(
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
                    ECGroup::P521);
            }
            else if (curveName == "P-384")
            {
                curves[curveName] = std::make_shared<cECPrimeField>(
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
                    ECGroup::P384);
            }
            else
            {
                throw std::runtime_error("Unknown curve: " + curveName);
            }
        }
        return curves[curveName];
    }
};
std::map<std::string, std::shared_ptr<cECPrimeField>> CurveRegistry::curves;

cECPoint::cECPoint()
{
    x = BN_secure_new();
    y = BN_secure_new();
}

cECSignature::cECSignature()
{
    R = BN_new();
    S = BN_new();
}

cECKey::cECKey(ECGroup group)
{
    this->group = group;
    this->priv = BN_secure_new();
}

cECPrimeField *cECKey::getGroup()
{
    return CurveRegistry::GetCurve(ECGroupString(this->group)).get();
}

bool isPointAtInfinity(cECPoint *p)
{
    return (BN_is_zero(p->x) && BN_is_zero(p->y));
}

void setPointToInfinity(cECPoint *p)
{
    BN_zero(p->x);
    BN_zero(p->y);
}

void ECCopyPoint(cECPoint *to, cECPoint *from)
{
    BN_copy(to->x, from->x);
    BN_copy(to->y, from->y);
}

void ECdouble(cECPrimeField *g,
              cECPoint *final_ret,
              cECPoint *a,
              BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);

    // Our return point so we do not mess with the final point until we are
    // finished
    cECPoint *ret = new cECPoint();
    ECCopyPoint(ret, a);

    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *tmp3 = BN_CTX_get(ctx);
    BIGNUM *x3 = BN_CTX_get(ctx);
    BIGNUM *x2 = BN_CTX_get(ctx);
    BIGNUM *y2 = BN_CTX_get(ctx);
    BIGNUM *zero = BN_CTX_get(ctx);
    BN_set_word(zero, 0);

    BN_copy(x3, ret->x);
    BN_copy(x2, ret->x);
    BN_copy(y2, ret->y);

    BN_mul_word(x3, 3);
    BN_mul_word(x2, 2);
    BN_mul_word(y2, 2);

    /* (3x * x + Acurve) * modinv( 2y, Pcurve ) % Pcurve */
    BN_mul(tmp, x3, ret->x, ctx);
    BN_add(tmp, tmp, g->a);              /* tmp holds 3x^2+Acurve  */
    BN_mod_inverse(tmp2, y2, g->p, ctx); /* tmp2 holds 2y^-1 mod( pCurve )*/
    BN_mod(tmp2, tmp2, g->p, ctx);
    BN_mul(tmp, tmp, tmp2, ctx); /* tmp now holds lambda */
    BN_mul(tmp2, tmp, tmp, ctx); /* tmp2 now holds lambda^2 */
    BN_sub(tmp3, tmp2, x2);
    BN_mod(ret->x, tmp3, g->p, ctx);

    BN_sub(tmp2, a->x, ret->x);  /* tmp2 now holds X - ret.x */
    BN_mul(tmp, tmp, tmp2, ctx); /* tmp now holds lambda * (X - ret.x) */
    BN_sub(tmp, tmp, a->y);      /* tmp now holds lambda * (X - ret.x) - Y */
    BN_mod(ret->y, tmp, g->p,
           ctx); /* ret->y now holds ( lambda * (X - ret.x) - Y ) mod P */

    if (BN_cmp(ret->x, zero) == -1)
        BN_add(ret->x, ret->x, g->p);

    if (BN_cmp(ret->y, zero) == -1)
        BN_add(ret->y, ret->y, g->p);
    ECCopyPoint(final_ret, ret);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    delete ret;
}

void ECadd(cECPrimeField *g,
           cECPoint *final_out,
           cECPoint *a,
           cECPoint *b,
           BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    cECPoint *res = new cECPoint();
    BIGNUM *lambda = BN_CTX_get(ctx);
    BIGNUM *tmpAddSub = BN_CTX_get(ctx);
    BIGNUM *tmpInv = BN_CTX_get(ctx);
    BIGNUM *tmpMul = BN_CTX_get(ctx);
    BIGNUM *zero = BN_CTX_get(ctx);
    BN_set_word(zero, 0);
    if (isPointAtInfinity(a) && isPointAtInfinity(b))
    {
        setPointToInfinity(res);
        goto ending;
    }
    else if (isPointAtInfinity(a))
    {
        ECCopyPoint(res, b);
        goto ending;
    }
    else if (isPointAtInfinity(b))
    {
        ECCopyPoint(res, a);
        goto ending;
    }
    else if (!BN_cmp((a->x), (b->x)) && !BN_cmp((a->y), (b->y)))
    {
        BN_mod(tmp, a->y, (g->p), ctx);
        if (BN_is_zero(tmp))
        {
            setPointToInfinity(res);
            goto ending;
        }
        ECdouble(g, res, a);
        goto ending;
    }
    else
    {
        BN_sub(tmp, b->x, a->x);
        BN_mod(tmp, tmp, g->p, ctx);
        if (BN_is_zero(tmp))
        {
            setPointToInfinity(res);
            goto ending;
        }

        BN_sub(tmpAddSub, b->x, a->x);
        BN_mod_inverse(tmpInv, tmpAddSub, g->p, ctx);
        BN_sub(tmpAddSub, b->y, a->y);
        BN_mul(lambda, tmpAddSub, tmpInv, ctx);

        BN_mul(tmpMul, lambda, lambda, ctx);
        BN_add(tmpAddSub, a->x, b->x);
        BN_sub(tmpAddSub, tmpMul, tmpAddSub);
        BN_mod(res->x, tmpAddSub, g->p, ctx);

        BN_sub(tmpAddSub, a->x, res->x);
        BN_mul(tmpMul, lambda, tmpAddSub, ctx);
        BN_sub(tmpAddSub, tmpMul, a->y);
        BN_mod(res->y, tmpAddSub, g->p, ctx);

        if (BN_cmp(res->x, zero) == -1)
            BN_add(res->x, res->x, g->p);

        if (BN_cmp(res->y, zero) == -1)
            BN_add(res->y, res->y, g->p);

        goto ending;
    }
ending:
    ECCopyPoint(final_out, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    delete res;
}

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
    setPointToInfinity(QRes);
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

/* FIPS 186-5 6.4.1 */
int EC_GenerateSignature(cECKey &key, cECSignature &sig,
                                       const ByteArray &msg,
                                       DIGEST_MODE shaMode,
                                       char *KSecret)
{
    int retCode = -1;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *k = BN_CTX_get(ctx);
    BIGNUM *kInv = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *E = BN_CTX_get(ctx);
    cECPrimeField *group = key.getGroup();
    cECPoint *RPoint = new cECPoint();

    /* Step 1 - 2 */
    ByteArray hash = Hasher::hash(msg, shaMode);
    int NLen = BN_num_bits(group->n); /* N = len(n) */
    int HLen = Hasher::getReturnLength(shaMode) * 8;
    BN_bin2bn(hash.data(), Hasher::getReturnLength(shaMode), tmp);
    if (HLen > NLen)
        BN_rshift(E, tmp, HLen - NLen);
    else
        BN_copy(E, tmp);

    /* Step 3 - 4 */
    /* Add in forcing a KSecret for utilization with test suite */
    if (KSecret == NULL)
    {
        BN_rand_range_ex(k, group->n, 0, ctx);
    }
    else
    {
        BN_hex2bn(&k, KSecret);
    }
    BN_mod_inverse(kInv, k, group->n, ctx);

    /* Step 5 */
    ECScalarMult(group, RPoint, k, group->G);

    /* Step 6 - 8 */
    BN_mod(sig.R, RPoint->x, group->n, ctx);

    /* Step 9 */
    BN_mul(tmp, sig.R, key.priv, ctx);
    BN_add(tmp, tmp, E);
    BN_mod_mul(sig.S, kInv, tmp, group->n, ctx);

    /* Step 10 */
    BN_zero(k);
    BN_zero(kInv);

    /* Step 11 */
    if (BN_is_zero(sig.S) || BN_is_zero(sig.R))
    {
        retCode = -1;
        goto ending;
    }
    retCode = 0;
ending:
    delete RPoint;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retCode;
}

/* FIPS 186-5 6.4.2 */
int EC_VerifySignature(cECKey &key, cECSignature &sig,
                                     const ByteArray msg,
                                     DIGEST_MODE shaMode)
{
    int retCode = -1;
    cECPrimeField *D = key.getGroup();
    cECPoint *Q = &key.pub;

    BN_CTX *ctx = BN_CTX_secure_new();
    BN_CTX_start(ctx);

    BIGNUM *sInv = BN_CTX_get(ctx);
    BIGNUM *E = BN_CTX_get(ctx);
    BIGNUM *u = BN_CTX_get(ctx);
    BIGNUM *u2 = BN_CTX_get(ctx);
    BIGNUM *v = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    cECPoint *addend1 = new cECPoint();
    cECPoint *addend2 = new cECPoint();
    cECPoint *RPoint = new cECPoint();

    // Step 2 - 3: Hash the message
    ByteArray hash = Hasher::hash(msg, shaMode);

    if (BN_is_zero(sig.R) || BN_is_zero(sig.S) || BN_ucmp(sig.R, D->n) >= 0 ||
        BN_ucmp(sig.S, D->n) >= 0)
        return -1; // Either R or S is not within 0, n-1

    // Step 3: Convert leftmost N bits of hash to integer
    int NLen = BN_num_bits(D->n); // N = len(n)
    int HLen = Hasher::getReturnLength(shaMode) * 8; // hash length in bits

    // Store hash in tmp
    BN_bin2bn(hash.data(), Hasher::getReturnLength(shaMode), tmp);

    // If the Hash bits > Order bits then only copy the higher order bits to E
    //  else fully copy the hash into E
    if (HLen > NLen)
        BN_rshift(E, tmp, HLen - NLen);
    else
        BN_copy(E, tmp);

    // Step 4: Compute s⁻¹ mod n
    BN_mod_inverse(sInv, sig.S, D->n, ctx);

    // Step 5: Compute u = e⋅s⁻¹ mod n, v = r⋅s⁻¹ mod n 
    BN_mod_mul(u, E, sInv, D->n, ctx);
    BN_mod_mul(v, sig.R, sInv, D->n, ctx);

    ECScalarMult(D, addend1, u, D->G);
    ECScalarMult(D, addend2, v, Q);
    ECadd(D, RPoint, addend1, addend2);

    if (isPointAtInfinity(RPoint))
    {
        retCode = -1;
        goto ending;
    }

    BN_nnmod(tmp, RPoint->x, D->n, ctx);

    if (BN_cmp(sig.R, tmp) == 0)
    {
        retCode = 0;
        goto ending;
    }
    else
    {
        retCode = -1;
        goto ending;
    }

ending:
    delete addend1;
    delete addend2;
    delete RPoint;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retCode;
}

// FIPS 186-4 B.4.2
int EC_GenerateKeyPair(cECKey &ret)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    cECKey key(ret.group);
    cECPrimeField *group = key.getGroup();
    BIGNUM *tmp = BN_dup(group->n);
    BN_sub(tmp, tmp, BN_value_one());

Generate:
    BN_priv_rand_range_ex(key.priv, tmp, 0, ctx);

    if (BN_cmp(key.priv, tmp) == 1)
    {
        goto Generate;
    }

    ECScalarMult(group, &key.pub, key.priv, group->G);
    ret = key;
    if (tmp)
        BN_clear_free(tmp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

std::string ECGroupString(ECGroup group)
{
    switch (group)
    {
    case P224:
        return "P-224";
        break;
    case P256:
        return "P-256";
        break;
    case P384:
        return "P-384";
        break;
    case P521:
        return "P-521";
        break;
    default:
        return "";
        break;
    }
    return "";
}

