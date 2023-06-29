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
#include "primes.hpp"
#include <math.h>


/* Using Miller-Robin */
bool miller_robin_is_prime(BIGNUM* n, int iterations, BN_CTX *ctx)
{
    BIGNUM *n1, *n2, *n4, *d, *a, *x, *y; 
    int s = 1;

    /* Confirm odd first */
    if(!BN_is_odd(n))
        return false;
    
    /* Need to be atleast > 3 else (n-1)=2*/
    if(!BN_get_word(n) > 3)
        return false;

    /* s > 0 and d odd > 0 such that (n-1) = (2^s)*d # by factoring out powers of 2 from n-1 (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)*/
    BN_CTX_start(ctx);
    n1 = BN_CTX_get(ctx);
    n2 = BN_CTX_get(ctx);
    n4 = BN_CTX_get(ctx);
    d = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    BN_sub(n1, n, BN_value_one());
    BN_sub(n2, n1, BN_value_one());
    BN_sub(n4, n2, BN_value_one());
    BN_sub(n4, n4, BN_value_one());
    /* Calculate s by checking largest number we can divide n-1 by 2^s */
    while(!BN_is_bit_set(n1, s))
        s++;

    /* (n-1)/(2^s) = d */
    BN_rshift(d, n1, s);

    /* Repeat 'k' times where k=iterations */
    for(int i = 0; i < iterations; i++)
    {
        
        BN_rand_range(a, n4);
        BN_add(a, a, BN_value_one());
        BN_add(a, a, BN_value_one());
        BN_mod_exp(x, a, d, n, ctx); /* a^d mod n */
        /* Repeat 's' times */
        for(int j = 0; j < s; j++)
        {
            BN_mod_sqr(y, x, n, ctx); /* x^2 mod n */
            if(  BN_is_one(y) &&
                !BN_is_one(x) &&
                 BN_cmp(x, n1) != 0 )
                return false;
            x = BN_dup(y);
        }
        if( !BN_is_one(y) )
            return false;
    }

    return true;
}

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



int generate_prime(BIGNUM *prime, int bits, BN_CTX *ctx = BN_CTX_new())
{
    /* Initialize memory with zeroes and temp vars */
    BIGNUM *temp;
    prime_t *mods = (prime_t*)OPENSSL_zalloc(sizeof(*mods)*NUMPRIMES);
    BN_CTX_start(ctx);
    temp = BN_CTX_get(ctx);
    int checks = 64; /* Use 64 < 2048 bits is being used. */
    int attempts = 0;
    loop:
        /* Generate a random number and set top and bottom bits */
        probable_prime(prime, bits, mods, ctx);
        if( BN_is_prime(prime, checks, NULL, ctx, NULL) == 0 )
        {
            printf("%d failed prime.\n", attempts);
            attempts++;
            goto loop;
        }
    printf("[%d] %s passed prime test.\n", attempts, BN_bn2dec(prime));
    OPENSSL_free(mods);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

int generatePrimes(int bits, int testingMR)
{
    int primes = 2, quo = 0, rmd = 0, bitsr[2];
    quo = bits / primes;
    rmd = bits % primes;
    if(testingMR)
    {
        int failed = 0, success = 0;
        BIGNUM* results[200];
        for(int z = 0; z < 200; z++)
        {
           results[z] = BN_new();
           generate_prime(results[z], 1024); 
        }

        for(int z = 0; z < 200; z++)
        {
            miller_robin_is_prime(results[z], 1000) ? success++ : failed++;
        }
        printf("\n%d succeeded %d failed.\n", success, failed);
    }
    else
    {
        BIGNUM* results[primes];
    /* Fill the bits array with quotient bit size based on number of primes (Only 2 in this case)*/
        for (int i = 0; i < primes; i++)
        {
            bitsr[i] = (i < rmd) ? quo + 1 : quo;
            results[i] = BN_new();
            generate_prime(results[i], bitsr[i]);
        }
    }
   
    return 0;
}