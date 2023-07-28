#include "inc/crypto/ec.hpp"
#include "inc/math/primes.hpp"
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <math.h>
#include "inc/hash/sha.hpp"
#include "inc/tests/test.hpp"


/* FIPS 186-4 */
/* 1. Curve over prime field, identified by P-xxx */
/* E: y^2 = x^3-3x+b (mod p) */




/*

SP 800-56 5.6.1.2 ECC Key-Pair Generation

TODO:
    Define a structure to hold the key
    Define a structure to hold a point


    Generate the private key within the range of 0, order
    From the private key define it as a new point within the group
    Then multiply 
*/

/* Prime256v1 */

BIGNUM *zero = BN_new();
BIGNUM *BN_value_zero()
{
    BN_set_word(zero, 0);
    return zero;
}

Prime256v1::Prime256v1()
{
        char *p = (char*)"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        char *a = (char*)"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        char *b = (char*)"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        char *Gx =(char*)"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        char *Gy =(char*)"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        char *n =(char*)"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

        BN_hex2bn(&this->p, p);
        BN_hex2bn(&this->a, a);
        BN_hex2bn(&this->b, b);
        BN_hex2bn(&this->n, n);
        BN_hex2bn(&(this->G->x), Gx);
        BN_hex2bn(&(this->G->y), Gy);
}

PrimeTestField::PrimeTestField()
 {
        char *p = (char*)"11";
        char *a = (char*)"1";
        char *b = (char*)"7";
        char *Gx = (char*)"1";
        char *Gy = (char*)"3";
        char *n = (char*)"0";

        BN_hex2bn(&this->p, p);
        BN_hex2bn(&this->a, a);
        BN_hex2bn(&this->b, b);
        BN_hex2bn(&this->n, n);
        BN_hex2bn(&(this->G->x), Gx);
        BN_hex2bn(&(this->G->y), Gy);
}

cECSignature::cECSignature()
{
    R = BN_new();
    S = BN_new();
}

bool isPointAtInfinity(cECPoint *p)
{
    return ( BN_is_zero(p->x) && BN_is_zero(p->y) );
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

void ECdouble(cECPrimeField *g, cECPoint *final_ret, cECPoint *a, BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    cECPoint *ret = new cECPoint();
    ECCopyPoint(ret, a);

    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *tmp3 = BN_CTX_get(ctx);
    BIGNUM *x3 = BN_CTX_get(ctx);
    BIGNUM *x2 = BN_CTX_get(ctx);
    BIGNUM *y2 = BN_CTX_get(ctx);

    BN_copy(x3, ret->x);
    BN_copy(x2, ret->x);
    BN_copy(y2, ret->y);

    BN_mul_word(x3, 3);
    BN_mul_word(x2, 2);
    BN_mul_word(y2, 2);

    /* (3x * x + Acurve) * modinv( 2y, Pcurve ) % Pcurve */
    BN_mul(tmp, x3, ret->x, ctx);
    BN_add(tmp, tmp, g->a);                          /* tmp holds 3x^2+Acurve  */
    BN_mod_inverse(tmp2, y2, g->p, ctx);    /* tmp2 holds 2y^-1 mod( pCurve )*/
    BN_mod(tmp2, tmp2, g->p, ctx);
    BN_mul(tmp, tmp, tmp2, ctx);           /* tmp now holds lambda */
    BN_mul(tmp2, tmp, tmp, ctx);           /* tmp2 now holds lambda^2 */
    BN_sub(tmp3, tmp2, x2);
    BN_mod(ret->x, tmp3, g->p, ctx);

    BN_sub(tmp2, a->x, ret->x);                     /* tmp2 now holds X - ret.x */
    BN_mul(tmp, tmp, tmp2, ctx);           /* tmp now holds lambda * (X - ret.x) */ 
    BN_sub(tmp, tmp, a->y);                         /* tmp now holds lambda * (X - ret.x) - Y */
    BN_mod(ret->y, tmp, g->p, ctx);        /* ret->y now holds ( lambda * (X - ret.x) - Y ) mod P */

    if( BN_cmp(ret->x, BN_value_zero()) == -1 )
        BN_add(ret->x, ret->x, g->p);

        
    if( BN_cmp(ret->y, BN_value_zero()) == -1 )
        BN_add(ret->y, ret->y, g->p);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ECCopyPoint(final_ret, ret);
}

void ECadd(cECPrimeField *g, cECPoint *final_out, cECPoint *a, cECPoint *b, BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    cECPoint *res = new cECPoint();
    if(isPointAtInfinity(a) && isPointAtInfinity(b))
    {
        setPointToInfinity(res);
        goto ending;
    }
    else if(isPointAtInfinity(a))
    {
        ECCopyPoint(res, b);
        goto ending;
    }
    else if(isPointAtInfinity(b))
    {
        ECCopyPoint(res, a);
        goto ending;
    }
    else if(!BN_cmp( (a->x), (b->x)) && !BN_cmp((a->y), (b->y)) )
    {
        BN_mod(tmp, a->y, (g->p), ctx);
        if(BN_is_zero(tmp))
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
        if( BN_is_zero(tmp) )
        {
            setPointToInfinity(res);
            goto ending;
        }

        BIGNUM *lambda = BN_CTX_get(ctx);
        BIGNUM *tmpAddSub = BN_CTX_get(ctx);
        BIGNUM *tmpInv = BN_CTX_get(ctx);
        BIGNUM *tmpMul = BN_CTX_get(ctx);

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

        
        if( BN_cmp(res->x, BN_value_zero()) == -1 )
            BN_add(res->x, res->x, g->p);

            
        if( BN_cmp(res->y, BN_value_zero()) == -1 )
            BN_add(res->y, res->y, g->p);

        goto ending;
    }
    ending:
    ECCopyPoint(final_out, res);
    BN_CTX_end(ctx);
}

void ECScalarMult(cECPrimeField *g, cECPoint *Q_output, BIGNUM *scalar, cECPoint *Point, BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    int i = 0;
    cECPoint *temp = new cECPoint();
    cECPoint *PointCopy = new cECPoint();
    cECPoint *QRes = new cECPoint();
    ECCopyPoint(PointCopy, Point);
    setPointToInfinity(QRes);
    for(i = BN_num_bits(scalar); i>=0; i--)
    {
        if( BN_is_bit_set(scalar, i) )
            break;
    }

    for(int j = 0; j <= i; j++)
    {
        if( BN_is_bit_set(scalar, j) )
        {
            ECadd(g, temp, QRes, PointCopy);
            ECCopyPoint(QRes, temp);
        }
        ECdouble(g, temp, PointCopy);
        ECCopyPoint(PointCopy, temp);
    }
    BN_CTX_end(ctx);
    ECCopyPoint(Q_output, QRes);
}

int test_math()
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    cECPrimeField *group = new PrimeTestField();
    cECPoint *ga = new cECPoint();
    ga->x = BN_copy(ga->x, group->G->x);
    ga->y = BN_copy(ga->y, group->G->y);

    printf("GAx: %s\n", BN_bn2dec(ga->x));
    printf("GAy: %s\n", BN_bn2dec(ga->y));
    cECPoint *initial13 = new cECPoint();
    cECPoint *result = new cECPoint();
    ECCopyPoint(initial13, ga);
    setPointToInfinity(result);
    for(int i = 0; i < 5; i++)
    {
        printf("Result Addition {%s, %s} + ", BN_bn2dec(result->x), BN_bn2dec(result->y));
        ECadd(group, result, initial13, result);
        printf("{%s, %s} = { %s, %s }\n", BN_bn2dec(ga->x), BN_bn2dec(ga->y), BN_bn2dec(result->x), BN_bn2dec(result->y));
    }
    BIGNUM *scalar = BN_CTX_get(ctx);
    
    for(int i = 0; i < 10; i++)
    {
        BN_set_word(scalar, i);
        ECScalarMult(group, result, scalar, initial13);
        printf("Result Multiply {%s, %s} * %s = { %s, %s }\n", BN_bn2dec(initial13->x), BN_bn2dec(initial13->y), BN_bn2dec(scalar), BN_bn2dec(result->x), BN_bn2dec(result->y));
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

/* FIPS 186-5 6.3.1 */
int ec_generate_signature(cECSignature *sig, char *msg, cECKey *key, char *KSecret)
{
    int retCode = -1;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *k = BN_CTX_get(ctx);
    BIGNUM *kInv = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *E = BN_CTX_get(ctx);
    cECPoint *RPoint = new cECPoint();

    /* Step 1 - 2 */
    SHA_Context *shaCtx = SHA_Context_new(SHA_512);
    uint8_t hash[ getSHAReturnLengthByMode(shaCtx->mode) ];
    sha_update( (uint8_t*)msg, strlen(msg), shaCtx);
    sha_digest(hash, shaCtx);
    int NLen = BN_num_bits( key->group->n ); /* N = len(n) */
    int HLen = getSHAReturnLengthByMode(shaCtx->mode)*8;
    BN_bin2bn(hash, getSHAReturnLengthByMode(shaCtx->mode), tmp);
    if( HLen > NLen )
        BN_rshift(E, tmp, HLen - NLen);
    else
        BN_copy(E, tmp);

    /* Step 3 - 4 */
    if(KSecret == NULL)
    {
        BN_rand_range_ex(k, key->group->n, 0, ctx);
    }
    else
    {
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

    //printf("k:  %s\n", BN_bn2hex(k));
    /* Step 10 */
    BN_zero(k);
    BN_zero(kInv);

    /* Step 11 */
    if( BN_is_zero(sig->S) || BN_is_zero(sig->R) )
    {
        printf("%s\n%s\n", BN_bn2hex(sig->S), BN_bn2hex(sig->R));
        retCode = -1;
        goto ending;
    }
    retCode = 0;
    //printf("R:  %s\nS:  %s\n", BN_bn2hex(sig->R), BN_bn2hex(sig->S));
    ending:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retCode;
}

/* FIPS 186-5 6.4.2 */
int ec_verify_signature( cECSignature *sig, char *msg, cECPrimeField *D, cECPoint *Q )
{
    int retCode = -1;

    BN_CTX *ctx = BN_CTX_secure_new();
    BN_CTX_start(ctx);

    BIGNUM *sInv = BN_CTX_get(ctx);
    BIGNUM *E = BN_CTX_get(ctx);
    BIGNUM *u = BN_CTX_get(ctx);
    BIGNUM *v = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    cECPoint *addend1 = new cECPoint();
    cECPoint *addend2 = new cECPoint();
    cECPoint *RPoint = new cECPoint();

    /* Step 2 - 3 */
    SHA_Context *shaCtx = SHA_Context_new(SHA_512);
    uint8_t hash[ getSHAReturnLengthByMode(shaCtx->mode) ];
    sha_update( (uint8_t*)msg, strlen(msg), shaCtx);
    sha_digest(hash, shaCtx);
    BN_bin2bn(hash, getSHAReturnLengthByMode(shaCtx->mode), tmp);
    int NLen = BN_num_bits( D->n ); /* N = len(n) */
    int HLen = getSHAReturnLengthByMode(shaCtx->mode)*8;
    if( HLen > NLen )
        BN_rshift(E, tmp, HLen - NLen);
    else
        BN_copy(E, tmp);

    /* Step 4 */
    BN_mod_inverse(sInv, sig->S, D->n, ctx);

    /* Step 5 */
    BN_mod_mul(u, E, sInv, D->n, ctx);
    BN_mod_mul(v, sig->R, sInv, D->n, ctx);


    ECScalarMult(D, addend1, u, D->G);
    ECScalarMult(D, addend2, v, Q);

    ECadd(D, RPoint, addend1, addend2);

    BN_mod(tmp, RPoint->x, D->n, ctx);

    if(BN_cmp(sig->R, tmp) == 0)
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
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return retCode;
}

/* FIPS 186-4 B.4.2 */
int ec_generate_key( cECKey *ret )
{
    
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    cECKey key;
    key.group = new Prime256v1();
    BIGNUM *tmp = BN_dup(key.group->n);
    BN_sub(tmp, tmp, BN_value_one());
    //printf("N:  %s\n", BN_bn2hex(key.group->n));
    //printf("Gx: %s\n", BN_bn2hex(key.group->G->x));
    //printf("Gy: %s\n", BN_bn2hex(key.group->G->y));

    Generate:
        BN_priv_rand_range_ex(key.priv, tmp, 0, ctx);
    
    if(BN_cmp(key.priv, tmp) == 1)
    {
        goto Generate;
    }
    ECScalarMult(key.group, key.pub, key.priv, key.group->G);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret->group = key.group;
    ret->priv = key.priv;
    ret->pub = key.pub;
    return 0;
}

int ec_sign_message(cECSignature *sig, cECKey *key, char *msg)
{
    cECKey *myKey2 = new cECKey();
    cECSignature *mySig2 = new cECSignature();
    if(key == NULL)
    {
        key = new cECKey();
        ec_generate_key(key);
    }

    if(sig == NULL)
    {
        sig = new cECSignature();
        if(ec_generate_signature(sig, msg, key) != 0)
            printf("Failed to generate signature\n");
    }
    ec_generate_key(myKey2);

    //printf("D:  %s\n", BN_bn2hex(myKey->priv));
    //printf("Qx: %s\n", BN_bn2hex(myKey->pub->x));
    //printf("Qy: %s\n", BN_bn2hex(myKey->pub->y));

    
   

    if(ec_generate_signature(mySig2, msg, myKey2) != 0)
        printf("Failed to generate signature\n");

    printf("Verifying against correct signature: %s\n", ec_verify_signature(sig, msg, key->group, key->pub)==0 ? "Passed!" : "Failed!");
    printf("Verifying against wrong signature: %s\n", ec_verify_signature(mySig2, msg, key->group, key->pub)==-1 ? "Passed!" : "Failed!");
    printf("Verifying against wrong key: %s\n", ec_verify_signature(sig, msg, myKey2->group, myKey2->pub)==-1 ? "Passed!" : "Failed!");
    printf("Verifying against wrong message: %s\n", ec_verify_signature(sig, "sdfsdfsdfsdfsd0xx00x0z98z8882828kzzkzkzku2228828", key->group, key->pub)==-1 ? "Passed!" : "Failed!");
     


    return 0;
}