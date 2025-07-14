#include "inc/math/primes.hpp"
#include <math.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

// This file is very temporary

/* Returns the discrepancies between the functions */
int testPrimesBetweenFuncs()
{
    BIGNUM *testPrime = BN_secure_new();
    int s = 0, j = 0;
    for (int i = 4; i < 17863; i++)
    {
        BN_set_word(testPrime, i);
        if (miller_rabin_is_prime(testPrime, 64))
            if (BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
                s++;
            else
                j++;
        else if (BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
            j++;
    }
    printf("Primes found: %d Discrepancies between other func: %d\n", s, j);
    BN_free(testPrime);

    return j;
}
