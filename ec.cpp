#include "inc/crypto/ec.hpp"
#include "inc/hash/sha.hpp"
#include "inc/math/primes.hpp"
#include "inc/tests/test.hpp"
#include "inc/utils/bytes.hpp"
#include <linux/random.h>
#include <math.h>
#include <openssl/bn.h>
#include <sys/syscall.h>
#include <unistd.h>
/* SP 800-186: Domain parameters are from */

/* Prime256v1 */

Prime224::Prime224() {
  char *p = (char *)"ffffffffffffffffffffffffffffffff000000000000000000000001";
  char *a = (char *)"fffffffffffffffffffffffffffffffefffffffffffffffffffffffe";
  char *b = (char *)"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4";
  char *Gx = (char *)"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
  char *Gy = (char *)"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
  char *n = (char *)"ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d";

  BN_hex2bn(&this->p, p);
  BN_hex2bn(&this->a, a);
  BN_hex2bn(&this->b, b);
  BN_hex2bn(&this->n, n);
  BN_hex2bn(&(this->G->x), Gx);
  BN_hex2bn(&(this->G->y), Gy);
}


cECPoint::~cECPoint()
{
    BN_clear_free(this->x);
    BN_clear_free(this->y);
}

cECSignature::~cECSignature()
{
    BN_clear_free(this->R);
    BN_clear_free(this->S);
}

cECKey::~cECKey()
{
    delete this->group;
    delete this->pub;
    BN_clear_free(this->priv);
}

cECPrimeField::~cECPrimeField()
{
    BN_clear_free(this->p);
    BN_clear_free(this->a);
    BN_clear_free(this->b);
    BN_clear_free(this->n);
    delete this->G;
}


Prime256v1::Prime256v1() {
  char *p =
      (char
           *)"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
  char *a =
      (char
           *)"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
  char *b =
      (char
           *)"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
  char *Gx =
      (char
           *)"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
  char *Gy =
      (char
           *)"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
  char *n =
      (char
           *)"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

  BN_hex2bn(&this->p, p);
  BN_hex2bn(&this->a, a);
  BN_hex2bn(&this->b, b);
  BN_hex2bn(&this->n, n);
  BN_hex2bn(&(this->G->x), Gx);
  BN_hex2bn(&(this->G->y), Gy);
}

Prime384::Prime384() {
  char *p = (char *)"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffeffffffff0000000000000000ffffffff";
  char *a = (char *)"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffeffffffff0000000000000000fffffffc";
  char *b = (char *)"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f50"
                    "13875ac656398d8a2ed19d2a85c8edd3ec2aef";
  char *Gx = (char *)"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e08"
                     "2542a385502f25dbf55296c3a545e3872760ab7";
  char *Gy = (char *)"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b"
                     "5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
  char *n = (char *)"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4"
                    "372ddf581a0db248b0a77aecec196accc52973";

  BN_hex2bn(&this->p, p);
  BN_hex2bn(&this->a, a);
  BN_hex2bn(&this->b, b);
  BN_hex2bn(&this->n, n);
  BN_hex2bn(&(this->G->x), Gx);
  BN_hex2bn(&(this->G->y), Gy);
}

Prime521::Prime521() {
  char *p = (char *)"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffffffffffffff";
  char *a = (char *)"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffc";
  char *b = (char *)"051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b4899"
                    "18ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1e"
                    "f451fd46b503f00";
  char *Gx = (char *)"0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af"
                     "606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429"
                     "bf97e7e31c2e5bd66";
  char *Gy = (char *)"11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd"
                     "17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24"
                     "088be94769fd16650";
  char *n = (char *)"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aeb"
                    "b6fb71e91386409";

  BN_hex2bn(&this->p, p);
  BN_hex2bn(&this->a, a);
  BN_hex2bn(&this->b, b);
  BN_hex2bn(&this->n, n);
  BN_hex2bn(&(this->G->x), Gx);
  BN_hex2bn(&(this->G->y), Gy);
}

cECSignature::cECSignature() {
  R = BN_new();
  S = BN_new();
}

bool isPointAtInfinity(cECPoint *p) {
  return (BN_is_zero(p->x) && BN_is_zero(p->y));
}

void setPointToInfinity(cECPoint *p) {
  BN_zero(p->x);
  BN_zero(p->y);
}

void ECCopyPoint(cECPoint *to, cECPoint *from) {
  BN_copy(to->x, from->x);
  BN_copy(to->y, from->y);
}

void ECCopyGroup(cECPrimeField *to, cECPrimeField *from)
{
    BN_copy(to->p, from->p);
    BN_copy(to->a, from->a);
    BN_copy(to->b, from->b);
    BN_copy(to->n, from->n);
    ECCopyPoint(to->G, from->G);
}

void ECCopyKey(cECKey *to, cECKey *from)
{
    
    ECCopyGroup(to->group, from->group);
    ECCopyPoint(to->pub, from->pub);
    BN_copy(to->priv, from->priv);
}

void ECdouble(cECPrimeField *g, cECPoint *final_ret, cECPoint *a,
              BN_CTX *ctx = BN_CTX_new()) {
  BN_CTX_start(ctx);
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

void ECadd(cECPrimeField *g, cECPoint *final_out, cECPoint *a, cECPoint *b,
           BN_CTX *ctx = BN_CTX_new()) {
  BN_CTX_start(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  cECPoint *res = new cECPoint();
  if (isPointAtInfinity(a) && isPointAtInfinity(b)) {
    setPointToInfinity(res);
    goto ending;
  } else if (isPointAtInfinity(a)) {
    ECCopyPoint(res, b);
    goto ending;
  } else if (isPointAtInfinity(b)) {
    ECCopyPoint(res, a);
    goto ending;
  } else if (!BN_cmp((a->x), (b->x)) && !BN_cmp((a->y), (b->y))) {
    BN_mod(tmp, a->y, (g->p), ctx);
    if (BN_is_zero(tmp)) {
      setPointToInfinity(res);
      goto ending;
    }
    ECdouble(g, res, a);
    goto ending;
  } else {
    BN_sub(tmp, b->x, a->x);
    BN_mod(tmp, tmp, g->p, ctx);
    if (BN_is_zero(tmp)) {
      setPointToInfinity(res);
      goto ending;
    }

    BIGNUM *lambda = BN_CTX_get(ctx);
    BIGNUM *tmpAddSub = BN_CTX_get(ctx);
    BIGNUM *tmpInv = BN_CTX_get(ctx);
    BIGNUM *tmpMul = BN_CTX_get(ctx);
    BIGNUM *zero = BN_CTX_get(ctx);
    BN_set_word(zero, 0);

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

void ECScalarMult(cECPrimeField *g, cECPoint *Q_output, BIGNUM *scalar,
                  cECPoint *Point, BN_CTX *ctx = BN_CTX_new()) {
  BN_CTX_start(ctx);
  int i = 0;
  cECPoint *temp = new cECPoint();
  cECPoint *PointCopy = new cECPoint();
  cECPoint *QRes = new cECPoint();
  ECCopyPoint(PointCopy, Point);
  setPointToInfinity(QRes);
  for (i = BN_num_bits(scalar); i >= 0; i--) {
    if (BN_is_bit_set(scalar, i))
      break;
  }

  for (int j = 0; j <= i; j++) {
    if (BN_is_bit_set(scalar, j)) {
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

int test_math() {
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  cECPrimeField *group = new Prime256v1();
  cECPoint *ga = new cECPoint();
  ga->x = BN_copy(ga->x, group->G->x);
  ga->y = BN_copy(ga->y, group->G->y);

  printf("GAx: %s\n", BN_bn2dec(ga->x));
  printf("GAy: %s\n", BN_bn2dec(ga->y));
  cECPoint *initial13 = new cECPoint();
  cECPoint *result = new cECPoint();
  ECCopyPoint(initial13, ga);
  setPointToInfinity(result);
  for (int i = 0; i < 5; i++) {
    printf("Result Addition {%s, %s} + ", BN_bn2dec(result->x),
           BN_bn2dec(result->y));
    ECadd(group, result, initial13, result);
    printf("{%s, %s} = { %s, %s }\n", BN_bn2dec(ga->x), BN_bn2dec(ga->y),
           BN_bn2dec(result->x), BN_bn2dec(result->y));
  }
  BIGNUM *scalar = BN_CTX_get(ctx);

  for (int i = 0; i < 10; i++) {
    BN_set_word(scalar, i);
    ECScalarMult(group, result, scalar, initial13);
    printf("Result Multiply {%s, %s} * %s = { %s, %s }\n",
           BN_bn2dec(initial13->x), BN_bn2dec(initial13->y), BN_bn2dec(scalar),
           BN_bn2dec(result->x), BN_bn2dec(result->y));
  }
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

/* FIPS 186-5 6.4.1 */
int FIPS_186_5_6_4_1_GenerateSignature(cECSignature *sig, char *msg,
                                       size_t msg_len, cECKey *key, SHA_MODE shaMode,
                                       char *KSecret) {
  int retCode = -1;
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  BIGNUM *k = BN_CTX_get(ctx);
  BIGNUM *kInv = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  BIGNUM *E = BN_CTX_get(ctx);
  cECPoint *RPoint = new cECPoint();

  /* Step 1 - 2 */
  SHA_Context *shaCtx = SHA_Context_new(shaMode);
  uint8_t hash[getSHAReturnLengthByMode(shaCtx->mode)];
  sha_update((uint8_t *)msg, msg_len, shaCtx);
  sha_digest(hash, shaCtx);
  int NLen = BN_num_bits(key->group->n); /* N = len(n) */
  int HLen = getSHAReturnLengthByMode(shaCtx->mode) * 8;
  BN_bin2bn(hash, getSHAReturnLengthByMode(shaCtx->mode), tmp);
  if (HLen > NLen)
    BN_rshift(E, tmp, HLen - NLen);
  else
    BN_copy(E, tmp);

  /* Step 3 - 4 */
  /* Add in forcing a KSecret for utilization with test suite */
  if (KSecret == NULL) {
    BN_rand_range_ex(k, key->group->n, 0, ctx);
  } else {
    BN_hex2bn(&k, KSecret);
  }
  BN_mod_inverse(kInv, k, key->group->n, ctx);

  /* Step 5 */
  ECScalarMult(key->group, RPoint, k, key->group->G);

  /* Step 6 - 8 */
  BN_mod(sig->R, RPoint->x, key->group->n, ctx);

  /* Step 9 */
  BN_mul(tmp, sig->R, key->priv, ctx);
  BN_add(tmp, tmp, E);
  BN_mod_mul(sig->S, kInv, tmp, key->group->n, ctx);

  /* Step 10 */
  BN_zero(k);
  BN_zero(kInv);

  /* Step 11 */
  if (BN_is_zero(sig->S) || BN_is_zero(sig->R)) {
    retCode = -1;
    goto ending;
  }
  retCode = 0;
ending:
  delete RPoint;
  delete shaCtx;
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return retCode;
}

/* Compute s^(-1) mod n using Montgomery multiplication */
int compute_inverse_mod_order(cECPrimeField *group, BIGNUM *result,
                              const BIGNUM *s, BN_CTX *ctx) {
  BIGNUM *n_minus_two = NULL, *tmp = NULL;
  BN_MONT_CTX *mont_ctx = NULL;
  int ret = -1;

  BN_CTX_start(ctx);
  BIGNUM *two = BN_CTX_get(ctx);
  BN_set_word(two, 2);

  n_minus_two = BN_CTX_get(ctx);
  tmp = BN_CTX_get(ctx);
  if (n_minus_two == NULL || tmp == NULL) {
    goto err;
  }

  /* Check if s is in [1, n-1] */
  if (BN_is_zero(s) || BN_ucmp(s, group->n) >= 0) {
    goto err;
  }

  /* Initialize Montgomery context if not already set */
  mont_ctx = BN_MONT_CTX_new();
  if (mont_ctx == NULL) {
    goto err;
  }
  if (!BN_MONT_CTX_set(mont_ctx, group->n, ctx)) {
    goto err;
  }

  /* Compute n-2 for Fermat's Little Theorem: s^(-1) = s^(n-2) mod n */
  if (!BN_sub(n_minus_two, group->n, two)) {
    goto err;
  }

  /* Compute s^(n-2) mod n using Montgomery multiplication */
  if (!BN_mod_exp_mont(result, s, n_minus_two, group->n, ctx, mont_ctx)) {
    goto err;
  }

  ret = 0;

err:
  BN_MONT_CTX_free(mont_ctx);
  BN_CTX_end(ctx);
  return ret;
}

/* FIPS 186-5 6.4.2 */
int FIPS_186_5_6_4_2_VerifySignature(cECSignature *sig, char *msg,
                                     size_t msg_len, cECPrimeField *D,
                                     cECPoint *Q, SHA_MODE shaMode) {
  int retCode = -1;

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

  if (sig == NULL || Q == nullptr || sig->R == NULL || sig->S == NULL)
    return -1; /* Fail */

  /* Step 2 - 3: Hash the message */
  SHA_Context *shaCtx = SHA_Context_new(shaMode);
  uint8_t hash[getSHAReturnLengthByMode(shaCtx->mode)];
  sha_update((uint8_t *)msg, msg_len, shaCtx);
  sha_digest(hash, shaCtx);

  if (BN_is_zero(sig->R) || BN_is_zero(sig->S) || BN_ucmp(sig->R, D->n) >= 0 ||
      BN_ucmp(sig->S, D->n) >= 0)
    return -1; /* Either R or S is not within 0, n-1 */

  /* Step 3: Convert leftmost N bits of hash to integer */

  /*
   * Was testing if the OpenSSL way of performing the bitshift is more reliable.
   * Didn't seem to be any difference between the original way vs this.
   * (This is likely still more secure though)
   */
  /*
  int nLen = BN_num_bits(D->n);
  int dgstLen = getSHAReturnLengthByMode(shaMode);
  if(8*dgstLen > nLen)
  {
      dgstLen = (nLen+7)/8;
  }

  BN_bin2bn(hash, dgstLen, E);

  if(8*dgstLen > nLen)
    BN_rshift(E, E, 8 - (nLen & 0x7));
  */

  int NLen = BN_num_bits(D->n); /* N = len(n) */
  int HLen =
      getSHAReturnLengthByMode(shaCtx->mode) * 8; /* hash length in bits */

  /* Store hash in tmp */
  BN_bin2bn(hash, getSHAReturnLengthByMode(shaCtx->mode), tmp);

  /* If the Hash bits > Order bits then only copy the higher order bits to E
   * else fully copy the hash into E
   */
  if (HLen > NLen)
    BN_rshift(E, tmp, HLen - NLen);
  else
    BN_copy(E, tmp);

  /* Step 4: Compute s⁻¹ mod n */
  BN_mod_inverse(sInv, sig->S, D->n, ctx);
  /* compute_inverse_mod_order(D, sInv, sig->S, ctx);
   * Another way I can do the inverse, more taxing and not sure I really need to
   * do this.*/

  /* Step 5: Compute u = e⋅s⁻¹ mod n, v = r⋅s⁻¹ mod n */
  BN_mod_mul(u, E, sInv, D->n, ctx);
  BN_mod_mul(v, sig->R, sInv, D->n, ctx);

  ECScalarMult(D, addend1, u, D->G);
  ECScalarMult(D, addend2, v, Q);
  ECadd(D, RPoint, addend1, addend2);

  if (isPointAtInfinity(RPoint)) {
    retCode = -1;
    goto ending;
  }

  BN_nnmod(tmp, RPoint->x, D->n, ctx);

  if (BN_cmp(sig->R, tmp) == 0) {
    retCode = 0;
    goto ending;
  } else {
    retCode = -1;
    goto ending;
  }

ending:
  delete addend1;
  delete addend2;
  delete RPoint;
  delete shaCtx;
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return retCode;
}

/* FIPS 186-4 B.4.2 */
int FIPS_186_4_B_4_2_KeyPairGeneration(cECKey *ret) {

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  cECKey *key = new cECKey();
  ret->group = new Prime256v1();
  key->group = new Prime256v1();
  BIGNUM *tmp = BN_dup(key->group->n);
  BN_sub(tmp, tmp, BN_value_one());

Generate:
  BN_priv_rand_range_ex(key->priv, tmp, 0, ctx);

  if (BN_cmp(key->priv, tmp) == 1) {
    goto Generate;
  }

  ECScalarMult(key->group, key->pub, key->priv, key->group->G);
  ECCopyKey(ret, key);
  delete key;
  if(tmp)
    BN_clear_free(tmp);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

/* This will utilize an ascii message and test itself */
int ec_sign_message_and_test(cECSignature *sig, cECKey *key, char *msg) {
  cECKey *myKey2 = new cECKey();
  cECSignature *mySig2 = new cECSignature();
  if (key == NULL) {
    key = new cECKey();
    FIPS_186_4_B_4_2_KeyPairGeneration(key);
  }

  if (sig == NULL) {
    sig = new cECSignature();
    if (FIPS_186_5_6_4_1_GenerateSignature(sig, msg, strlen(msg), key) != 0)
      printf("Failed to generate signature\n");
  }
  FIPS_186_4_B_4_2_KeyPairGeneration(myKey2);

  if (FIPS_186_5_6_4_1_GenerateSignature(mySig2, msg, strlen(msg), myKey2) != 0)
    printf("Failed to generate signature\n");

  printf("Verifying against correct signature: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, msg, strlen(msg), key->group,
                                          key->pub) == 0
             ? "Passed!"
             : "Failed!");
  printf("Verifying against wrong signature: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(mySig2, msg, strlen(msg), key->group,
                                          key->pub) == -1
             ? "Passed!"
             : "Failed!");
  printf("Verifying against wrong key: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, msg, strlen(msg), myKey2->group,
                                          myKey2->pub) == -1
             ? "Passed!"
             : "Failed!");
  char foobar[] = "sdfsdfsdfsdfsd0xx00x0z98z8882828kzzkzkzku2228828";
  printf("Verifying against wrong message: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, foobar, strlen(foobar),
                                          key->group, key->pub) == -1
             ? "Passed!"
             : "Failed!");

  return 0;
}
