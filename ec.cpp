#include "inc/crypto/ec.hpp"
#include "inc/math/primes.hpp"
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>


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

/* FIPS 186-4 B.5.2 */
int ec_generate_signature(cECSignature *sig, cECKey *key)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *k = BN_CTX_get(ctx);
    BIGNUM *kInv = BN_CTX_get(ctx);

    BN_rand_range_ex(k, key->group->n, 0, ctx);

    BN_mod_inverse(kInv, k, key->group->n, ctx);

    BN_CTX_end(ctx);

    sig->k = k;
    sig->kInv = kInv;
    return 0;
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
    printf("N:  %s\n", BN_bn2hex(key.group->n));
    printf("Gx: %s\n", BN_bn2hex(key.group->G->x));
    printf("Gy: %s\n", BN_bn2hex(key.group->G->y));

    Generate:
        BN_priv_rand_range_ex(key.priv, tmp, 0, ctx);
    
    if(BN_cmp(key.priv, tmp) == 1)
    {
        goto Generate;
    }
    ECScalarMult(key.group, key.pub, key.priv, key.group->G);
    
    printf("D:  %s\n", BN_bn2hex(key.priv));
    printf("Qx: %s\n", BN_bn2hex(key.pub->x));
    printf("Qy: %s\n", BN_bn2hex(key.pub->y));
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret->group = key.group;
    ret->priv = key.priv;
    ret->pub = key.pub;
    return 0;
}

int ec_sign_message(uint8_t *data)
{
    cECKey *myKey = new cECKey();
    cECSignature *mySig = new cECSignature();
    ec_generate_key(myKey);
    
    ec_generate_signature(mySig, myKey);
    return 0;
}