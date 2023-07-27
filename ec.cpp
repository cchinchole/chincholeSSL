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

cECPoint *getPointAtInfinity(cECPoint *p)
{
    BN_set_word(p->x, 0);
    BN_set_word(p->y, 0);
    return p;
}

void ECdouble(cECGroup *g, cECPoint *ret, cECPoint *a)
{
    BN_copy(ret->x, a->x);
    BN_copy(ret->y, a->y);

    BIGNUM *tmp = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BIGNUM *x3 = BN_dup(ret->x);
    BIGNUM *x2 = BN_dup(ret->x);
    BIGNUM *y2 = BN_dup(ret->y);

    BN_mul_word(x3, 3);
    BN_mul_word(x2, 2);
    BN_mul_word(y2, 2);

    /* (3x * x + Acurve) * modinv( 2y, Pcurve ) % Pcurve */
    BN_mul(tmp, x3, ret->x, BN_CTX_new());
    BN_add(tmp, tmp, g->a);                          /* tmp holds 3x^2+Acurve  */
    BN_mod_inverse(tmp2, y2, g->p, BN_CTX_new());    /* tmp2 holds 2y^-1 mod( pCurve )*/
    BN_mod(tmp2, tmp2, g->p, BN_CTX_new());
    BN_mul(tmp, tmp, tmp2, BN_CTX_new());           /* tmp now holds lambda */
    BN_mul(tmp2, tmp, tmp, BN_CTX_new());           /* tmp2 now holds lambda^2 */
    BN_sub(tmp3, tmp2, x2);
    BN_mod(ret->x, tmp3, g->p, BN_CTX_new());

    BN_sub(tmp2, a->x, ret->x);                     /* tmp2 now holds X - ret.x */
    BN_mul(tmp, tmp, tmp2, BN_CTX_new());           /* tmp now holds lambda * (X - ret.x) */ 
    BN_sub(tmp, tmp, a->y);                         /* tmp now holds lambda * (X - ret.x) - Y */
    BN_mod(ret->y, tmp, g->p, BN_CTX_new());        /* ret->y now holds ( lambda * (X - ret.x) - Y ) mod P */

    if( BN_cmp(ret->x, BN_value_zero()) == -1 )
        BN_add(ret->x, ret->x, g->p);

        
    if( BN_cmp(ret->y, BN_value_zero()) == -1 )
        BN_add(ret->y, ret->y, g->p);
}

cECPoint *ECadd(cECGroup *g, cECPoint *a, cECPoint *b, BN_CTX *ctx = BN_CTX_new())
{
    cECPoint *res = new cECPoint();
    BN_CTX_start(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    if(isPointAtInfinity(a) && isPointAtInfinity(b))
    {
        res = getPointAtInfinity(res);
        goto ending;
    }
    else if(isPointAtInfinity(a))
    {
        res = b;
        goto ending;
    }
    else if(isPointAtInfinity(b))
    {
        res = a;
        goto ending;
    }
    else if(!BN_cmp( (a->x), (b->x)) && !BN_cmp((a->y), (b->y)) )
    {
        BN_mod(tmp, a->y, (g->p), ctx);
        if(BN_is_zero(tmp))
        {
            res = getPointAtInfinity(res);
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
            res = getPointAtInfinity(res);
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
    BN_CTX_end(ctx);
    return res;
}

cECPoint *ECScalarMult(cECGroup *g, BIGNUM *scalar, cECPoint *Point, BN_CTX *ctx = BN_CTX_new())
{
    BN_CTX_start(ctx);
    int i = 0;
    cECPoint *temp = new cECPoint();
    cECPoint *PointCopy = new cECPoint();
    cECPoint *QRes = new cECPoint();
    BN_copy(PointCopy->x, Point->x);
    BN_copy(PointCopy->y, Point->y);
    QRes = getPointAtInfinity(QRes);
    for(i = BN_num_bits(scalar); i>=0; i--)
    {
        if( BN_is_bit_set(scalar, i) )
        {
            printf("[%d / 0] %d bit is set\n", BN_num_bits(scalar), i);
            break;
        }
    }

    for(int j = 0; j <= i; j++)
    {
        if( BN_is_bit_set(scalar, j) )
        {
            printf("LOOP 2: %d bit is set\n ", j);
            temp = ECadd(g, QRes, PointCopy);
            BN_copy(QRes->x, temp->x);
            BN_copy(QRes->y, temp->y);
        }
        ECdouble(g, temp, PointCopy);
        BN_copy(PointCopy->x, temp->x);
        BN_copy(PointCopy->y, temp->y);
        printf("Result thus far in nonbit set { %s, %s }\n", BN_bn2dec(QRes->x), BN_bn2dec(QRes->y));
    }
    BN_CTX_end(ctx);
    return QRes;
}

int ec_generate_key(  )
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    cECKey key;
    key.group = new Prime256v1();
    //key.group = new PrimeTestField();
    BIGNUM *tmp = BN_dup(key.group->n);
    BN_sub(tmp, tmp, BN_value_one());
    printf("%s\n", BN_bn2dec(tmp));
    printf("Gx: %s\n", BN_bn2hex(key.group->G->x));
    printf("Gy: %s\n", BN_bn2hex(key.group->G->y));


    
    Generate:
        BN_priv_rand_range_ex(key.priv, tmp, 0, ctx);
    
    if(BN_cmp(key.priv, tmp) == 1)
    {
        goto Generate;
    }
    key.pub = ECScalarMult(key.group, key.priv, key.group->G);
    
    printf("D:  %s\n", BN_bn2hex(key.priv));
    printf("Qx: %s\n", BN_bn2hex(key.pub->x));
    printf("Qy: %s\n", BN_bn2hex(key.pub->y));
    
    /*
    cECPoint *ga = new cECPoint();
    ga->x = BN_copy(ga->x, key.group->G->x);
    ga->y = BN_copy(ga->y, key.group->G->y);

    printf("GAx: %s\n", BN_bn2dec(ga->x));
    printf("GAy: %s\n", BN_bn2dec(ga->y));
    cECPoint *ret = new cECPoint();
    cECPoint *result = new cECPoint();
    BN_copy(ret->x, ga->x);
    BN_copy(ret->y, ga->y);
    result = ECadd(key.group, ret, ga);
    for(int i = 0; i < 5; i++)
    {
        printf("Result Addition {%s, %s} + ", BN_bn2dec(result->x), BN_bn2dec(result->y));
        result = ECadd(key.group, result, ga);
        printf("{%s, %s} = { %s, %s }\n", BN_bn2dec(ga->x), BN_bn2dec(ga->y), BN_bn2dec(result->x), BN_bn2dec(result->y));
    }
    ECdouble(key.group, ret, ga);
    BIGNUM *scalar = BN_CTX_get(ctx);
    BN_set_word(scalar, 50);
    
    result = ECScalarMult(key.group, scalar, ret);
    printf("Result Multiply { %s, %s }\n", BN_bn2dec(result->x), BN_bn2dec(result->y));
    */
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}