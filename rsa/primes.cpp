#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <chrono>
#include <vector>
#include <iostream>
#include "inc/primes.hpp"
#include <math.h>

int FIPS186_4_MR_Rounds(int nLen);
int FIPS186_5_MIN_AUX(int nLen);
int FIPS186_5_MAX_PROB_LEN(int nLen);

/* Using Miller-Rabin */
/* FIPS 186-4 C.3.1 */
/* Returns true for PROBABLY PRIME and false for COMPOSITE */
/* Refactored variable names for FIPS: n->w, s->a, a->b, y->z, m->m */
bool miller_rabin_is_prime(BIGNUM* w, int iterations, BN_CTX *ctx)
{
    BIGNUM *w1, *w2, *w4, *m, *b, *x, *z; 
    int a = 1;

    /* Confirm odd first */
    if(!BN_is_odd(w))
        return false;
    
    /* Need to be atleast > 3 else (n-1)=2*/
    if(!BN_get_word(w) > 3)
        return false;

    /* s > 0 and d odd > 0 such that (n-1) = (2^s)*d # by factoring out powers of 2 from n-1 (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)*/
    BN_CTX_start(ctx);
    w1 = BN_CTX_get(ctx);
    w2 = BN_CTX_get(ctx);
    w4 = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    BN_sub(w1, w, BN_value_one());
    BN_sub(w2, w1, BN_value_one());
    BN_sub(w4, w2, BN_value_one());
    BN_sub(w4, w4, BN_value_one());

    /* Calculate s by checking largest number we can divide n-1 by 2^s */
    while(!BN_is_bit_set(w1, a))
        a++;

    /* (n-1)/(2^s) = d */
    BN_rshift(m, w1, a);

    /* Repeat 'k' times where k=iterations */
    for(int i = 0; i < iterations; i++)
    {
            BN_rand_range(b, w4);
            BN_add(b, b, BN_value_one());
            BN_add(b, b, BN_value_one());
            BN_mod_exp(x, b, m, w, ctx); /* a^m mod n */
            /* Repeat 's' times */


        for(int j = 0; j < a; j++)
        {
            BN_mod_sqr(z, x, w, ctx); /* x^2 mod n */
            if(  BN_is_one(z) &&
                !BN_is_one(x) &&
                 BN_cmp(x, w1) != 0 )
                goto failure;
            x = BN_dup(z);
        }
        if( !BN_is_one(z) )
            goto failure;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return true;

    failure:
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return false;
}

/* These functions do not support auxiliary primes and as such cannot be used for FIPS prime generation or testing.*/
int probable_prime(BIGNUM *rnd, int bits, prime_t *mods, BN_CTX *ctx)
{
    BN_ULONG delta = 0;
    int divisions = 128; /* Divisions for 1024 (OpenSSL) */
    BN_ULONG maxDelta = MAXULONGSIZE-primes[divisions-1]; /* Maximum size of ULONG - the prime index of division for 1024 will return 0xFFFFFFFFFFFFFD30 */
    
    /* Using OpenSSL's random bit generator */
    /* Constrained to the top two bits being 1 with the number being odd: generates random bits of the given bits size (1024)*/
    repeat: /* Used if the rnd number failed */
        delta = 0;
        BN_priv_rand_ex(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0, ctx); /* The probability of generating a prime increases with leading one's https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural */

        /* Division test */
        for(int i = 1; i < divisions; i++)
        {
            BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]); /* Random Generated Num / prime table up to division (128) */
            mods[i] = (prime_t)mod;
        }
        loop:
            for(int i = 1; i < divisions; i++)
            {
                /* Check that the random number is prime and that the GCD of random-1 and prime index is 1 */
                if(delta <= 0x7fffffff) /* Check that we are within the prime segment */
                    if(square(primes[i]) > BN_get_word(rnd) + delta) /* Make sure we are within */
                        break;

                if( (mods[i] + delta) % primes[i] == 0 ) /* use the remainder + delta and divide by the prime table to check if composite*/
                {
                    /* Failed, had an even divide by primes */
                    /* Increase the delta and retry */
                    delta += 2;
                    if(delta > maxDelta)
                        goto repeat;
                    goto loop;
                }
            }
        BN_add_word(rnd, delta); /* Add the delta that gave us a prime to our random number */
        if(BN_num_bits(rnd) != bits)
            goto repeat; /* If we didn't generate the correct size then go again. */
    return 0;
}

int generate_prime(BIGNUM *prime, int bits, BN_CTX *ctx = BN_CTX_secure_new())
{
    /* Initialize memory with zeroes and temp vars */
    BIGNUM *temp;
    prime_t *mods = (prime_t*)OPENSSL_zalloc(sizeof(*mods)*NUMPRIMES);
    BN_CTX_start(ctx);
    temp = BN_CTX_get(ctx);
    int checks = FIPS186_4_MR_Rounds(bits);
    int attempts = 0;
    loop:
        /* Generate a random number and set top and bottom bits */
        probable_prime(prime, bits, mods, ctx);
        if(!miller_rabin_is_prime(prime, checks))    //if( BN_is_prime(prime, checks, NULL, ctx, NULL) == 0 )
            goto loop;
    OPENSSL_free(mods);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);



    return 0;
}

int generatePrimes(RSA_Params *rsa, int bits, int testingMR)
{
    int primes = 2, quo = 0, rmd = 0, bitsr[2];
    quo = bits / primes;
    rmd = bits % primes;
    BIGNUM *results[primes], *r1  = BN_secure_new(), *r2  = BN_secure_new();
    if(testingMR)
    {
        int failed = 0, success = 0;
        BIGNUM* rez[200];
        for(int z = 0; z < 200; z++)
        {
           rez[z] = BN_secure_new();
           generate_prime(rez[z], 1024); 
        }

        for(int z = 0; z < 200; z++)
        {
            miller_rabin_is_prime(rez[z], 1000) ? success++ : failed++;
        }

        for(int z = 0; z < 200; z++)
        {
            BN_free(rez[z]);
        }
        printf("\n%d succeeded %d failed.\n", success, failed);
    }
    else
    {
        /* Fill the bits array with quotient bit size based on number of primes (Only 2 in this case)*/
        for (int i = 0; i < primes; i++)
        {
            bitsr[i] = (i < rmd) ? quo + 1 : quo;
            results[i] = BN_secure_new();
            for(;;)
            {
                generate_prime(results[i], bitsr[i]);
                printf("Testing: %s\n", BN_bn2dec(results[i]));
                
                BN_sub(r2, results[i], BN_value_one());
                if(BN_mod_inverse(r1, r2, rsa->e, BN_CTX_secure_new()) != NULL)
                    break;
            }

        } 
    }
    printf("P found: %s\nQ found: %s\n", BN_bn2dec(results[0]), BN_bn2dec(results[1]));
    rsa->p = BN_dup(results[0]);
    rsa->q = BN_dup(results[1]);
   
    return 0;
}


/* FIPS 186-4-C.9 */
int FIPS186_4_COMPUTE_PROB_PRIME_FROM_AUX(BIGNUM *PRIV_PRIME_FACTOR, BIGNUM *X, BIGNUM *Xin, BIGNUM *r1, BIGNUM *r2, int nLen, BIGNUM *e, BN_CTX *ctx)
{
    BIGNUM *R, *r1mul2, *r1_mul2_r1, *temp, *tempPrivFactor;
    int bits = nLen >> 1;

    BN_CTX_start(ctx);
    R = BN_CTX_get(ctx);
    r1mul2 = BN_CTX_get(ctx);
    temp = BN_CTX_get(ctx);
    r1_mul2_r1 = BN_CTX_get(ctx);
    tempPrivFactor = BN_CTX_get(ctx);

    BN_mul_word(r1, 2);
    BN_mul(r1_mul2_r1, r1mul2, r2, ctx);
    BN_gcd(temp, r1mul2, r2, ctx);

    /* GCD(2r1, r1) != 1 */
    if(!BN_is_one(temp))
        return -1;

    /* R= (( r2^(-1) mod 2r1 ) * r2 ) - (( (2r1)^(-1) mod r2) * 2r1) Applying CRT, so that R=1 (mod2r1) and R = -1(modr2) */
    
    BN_mod_inverse(R, r2, r1mul2, ctx);
    BN_mul(R, R, r2, ctx);

    BN_mod_inverse(temp, r1mul2, r2, ctx);
    BN_mul(temp, temp, r1mul2, ctx);

    BN_sub(R, R, temp);



    if(Xin != NULL)
        BN_copy(X, Xin);

    for(;;)
    {
        /* Generate X within sqrt(2)(2^(nLen)/(2) - 1) and ( (2^(nLen)/2) - 1) Step 3 */    
        if(Xin == NULL)
        {
            BN_set_word(temp, sqrt(2)*pow(2, nLen/2 - 1) );
            BN_priv_rand_range_ex(X, temp, 0, ctx);
            BN_add_word(X, pow(2, nLen/2) - 1);
        }

        BN_mod_sub(PRIV_PRIME_FACTOR, R, X, r1_mul2_r1, ctx); /* Generate the private prime factor Step 4 */
        BN_add(PRIV_PRIME_FACTOR, PRIV_PRIME_FACTOR, X);

        for(int i = 0; i < 5 * nLen/2; i++)
        {
            if(BN_num_bits(PRIV_PRIME_FACTOR) > bits)
                if(Xin == NULL)
                    break;  /* Bad X generation so go back to step 3 */
                else
                    return 0; /* X was inputted if we make it here. */

            BN_copy(tempPrivFactor, PRIV_PRIME_FACTOR);
            BN_sub_word(tempPrivFactor, 1);

            if(BN_are_coprime(tempPrivFactor, e, ctx))
            {
                if(miller_rabin_is_prime(PRIV_PRIME_FACTOR, FIPS186_4_MR_Rounds(nLen), ctx))
                    goto ending;
            }

            BN_add(PRIV_PRIME_FACTOR, PRIV_PRIME_FACTOR, r1_mul2_r1);
        }
    }
    ending:
        BN_CTX_end(ctx);
        return 0;
}


/* FIPS 186-4-B.3.6 */
int FIPS186_4_FIND_AUX_PRIME(BIGNUM *n1, BIGNUM *Xn1, int kbits, BN_CTX *ctx)
{
    /* Start from Xn1 and find the FIRST integer that is a probable prime then return it. */
    BN_copy(n1, Xn1); /* Changed to copy to prevent mem leak */

    BN_set_flags(n1, BN_FLG_CONSTTIME);
    for(;;)
    {
        if(miller_rabin_is_prime(n1, FIPS186_4_MR_Rounds(kbits), ctx))
            break;
        else
            BN_add_word(n1, 2);
    }
    return 0;
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_GEN_PROB_PRIME(BIGNUM *n, BIGNUM *Xnout, BIGNUM *n1, BIGNUM *n2, BIGNUM *Xn, BIGNUM *Xn1, BIGNUM *Xn2, BIGNUM *e, int kbits, bool testParamsFilled, BN_CTX *ctx)
{    
    BIGNUM *tempN1, *tempN2, *tempXn1, *tempXn2;

    BN_CTX_start(ctx);
    if(testParamsFilled)
    {
        tempN1 = n1;
        tempN2 = n2;
        tempXn1 = Xn1;
        tempXn2 = Xn2;
    }
    else
    {
        tempN1 = BN_CTX_get(ctx);
        tempN2 = BN_CTX_get(ctx);
        tempXn1 = BN_CTX_get(ctx);
        tempXn2 = BN_CTX_get(ctx);
    }

    /* If this is a test, skip generation else will proceed to generate Xn1 and Xn2 */
    if(Xn1 == NULL)
    {
        BN_priv_rand_ex(tempXn1, FIPS186_5_MIN_AUX(kbits), BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx);
    }

    if(Xn2 == NULL)
    {     
        BN_priv_rand_ex(tempXn2, FIPS186_5_MIN_AUX(kbits), BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx);
    }

    /* Generate the auxilary primes now */
    FIPS186_4_FIND_AUX_PRIME(tempN1, tempXn1, kbits, ctx);
    FIPS186_4_FIND_AUX_PRIME(tempN2, tempXn2, kbits, ctx);

    /* Make sure the auxilary primes' sum are within the max length */
    if( (BN_num_bits(tempN1) + BN_num_bits(tempN2)) >= FIPS186_5_MAX_PROB_LEN(kbits)  )
        return -1;

    /* Finally generate the prime using the auxilary primes */
    FIPS186_4_COMPUTE_PROB_PRIME_FROM_AUX(Xnout, n, Xn, tempXn1, tempXn2, kbits, e, ctx);


    BN_CTX_end(ctx);
    return 0;
}

int ossl_rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,
                           int nbits)
{
    int bitlen = (nbits >> 1) - 100;

    if (!BN_sub(diff, p, q))
        return -1;
    BN_set_negative(diff, 0);

    if (BN_is_zero(diff))
        return 0;

    if (!BN_sub_word(diff, 1))
        return -1;
    return (BN_num_bits(diff) > bitlen);
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_GEN_PRIMES(RSA_Params *rsa, int bits, bool doACVP, ACVP_TEST *testParams)
{
    BIGNUM *Xpo = NULL, *Xqo = NULL, *tmp = NULL, 
    *p1 = NULL, *p2 = NULL, *q1 = NULL, *q2 = NULL, 
    *Xpout = NULL, *Xqout = NULL, 
    *Xp = NULL, *Xp1 = NULL, *Xp2 = NULL, *Xq = NULL, *Xq1 = NULL, *Xq2 = NULL;
    BN_CTX *ctx = BN_CTX_secure_new();
    bool testParamsFilled = false;
    if(doACVP)
    {
        Xp1 = testParams->Xp1;
        Xp2 = testParams->Xp2;
        Xp = testParams->Xp;
        p1 = testParams->p1;
        p2 = testParams->p2;

        Xq1 = testParams->Xq1;
        Xq2 = testParams->Xq2;
        Xq = testParams->Xq;
        q1 = testParams->q1;
        q2 = testParams->q2;
    }

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if(doACVP)
    {
        Xpo = Xpout;
        Xqo = Xqout;
    }
    else
    {
        Xpo = BN_CTX_get(ctx);
        Xqo = BN_CTX_get(ctx);
    }

    BN_set_flags(Xpo, BN_FLG_CONSTTIME);
    BN_set_flags(Xqo, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->p, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->q, BN_FLG_CONSTTIME);

    for(;;)
    {
        /* Generate the primes */
        FIPS186_4_GEN_PROB_PRIME(rsa->p, Xpo, p1, p2, Xp, Xp1, Xp2, rsa->e, bits, doACVP, ctx);
        FIPS186_4_GEN_PROB_PRIME(rsa->q, Xqo, q1, q2, Xq, Xq1, Xq2, rsa->e, bits, doACVP, ctx);

        if(ossl_rsa_check_pminusq_diff(tmp, Xpo, Xqo, bits) == 0)
            continue;
        if(ossl_rsa_check_pminusq_diff(tmp, rsa->p, rsa->q, bits) == 0)
            continue;

        break;
    }



    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}


/* Probable prime generation is within FIPS 186-4.C.7 */

/* Can return Xpout (the returned random number for generation of P)
 * Can return Xqout (the returned random number for generation of Q)
 * Can input Xp, Xg (the random numbers used during generatino of p,q)
 * Can input Xp1, Xp2 (the random numbers which will generate the auxiliary primes)
 */

/* Minimum rounds of M-R testing from 186-4-C-3.1 */
int FIPS186_4_MR_Rounds(int nLen)
{
    if(nLen <= 512)
        return 7;
    else if(nLen <= 1024)
        return 4;
    else if(nLen <= 1536)
        return 3;
    else if(nLen <= 3072)
        return 4;
    else
        return 5;
}

/* Minimum length of an auxilary prime from FIPS 186-5-A.1 */
int FIPS186_5_MIN_AUX(int nLen)
{
    if(nLen <= 3071)
        return 140;
    else if(nLen <= 4095)
        return 170;
    else if(nLen >= 4096)
        return 200;
    else
        return 200;
}

/*Maximum size of probable prime bitlength(p1+p2) from FIPS 186-5-A.1 */
int FIPS186_5_MAX_PROB_LEN(int nLen)
{
    if(nLen <= 3071)
        return 1007;
    else if(nLen <= 4095)
        return 1518;
    else if(nLen >= 4096)
        return 2030;
    else
        return 2030;
}