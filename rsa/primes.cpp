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


int probable_prime(BIGNUM *rnd, int bits, prime_t *mods, BN_CTX *ctx)
{
    BN_ULONG delta = 0;
    int divisions = 128; /* Divisions for 1024 (OpenSSL) */
    BN_ULONG maxDelta = MAXULONGSIZE-primes[divisions-1]; /* Maximum size of ULONG - the prime index of division for 1024 will return 0xFFFFFFFFFFFFFD30 */
    
    /* Using OpenSSL's random bit generator */
    /* Constrained to the top two bits being 1 with the number being odd: generates random bits of the given bits size (1024)*/
    repeat: /* Used if the rnd number failed */
        BN_priv_rand_ex(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0, ctx); /* The probability of generating a prime increases with leading one's https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural */

        /* Division test */
        for(int i = 1; i < divisions; i++)
        {
            BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]); /* Random Generated Num / prime table up to division (128) */
            mods[i] = (prime_t)mod;
        }
        delta = 0; /* Incase a failure occurred */
        loop:
            for(int i = 1; i < divisions; i++)
            {
                /* Check that the random number is prime and that the GCD of random-1 and prime index is 1 */
                if(delta <= 0x7fffffff) /* Check that we are within the prime segment */
                    if(square(primes[i]) > BN_get_word(rnd) + delta) /* Make sure we are within */
                        break;

                if( (mods[i] + delta) % primes[i] == 0 ) /* use the remainder + delta and divide to by the prime table to check if composite*/
                {
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

int generatePrimes(int bits)
{
    int primes = 2, quo = 0, rmd = 0, bitsr[2];
    quo = bits / primes;
    rmd = bits % primes;
    BIGNUM* results[2];

    /* Fill the bits array with quotient bit size based on number of primes (Only 2 in this case)*/
    for (int i = 0; i < primes; i++)
    {
        bitsr[i] = (i < rmd) ? quo + 1 : quo;
        results[i] = BN_new();
        generate_prime(results[i], bitsr[i]);
    }
    return 0;
}