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
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <openssl/rand.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "inc/logger.hpp"
#include "inc/defs.hpp"
#include "inc/rsa.hpp"
#include "inc/primes.hpp"

const int kBits = 2048;
int keylen;
char *pem_key;


/*
  * TODO:
  *   Make Encryption / Decryption FIPS Compliant
  *   Make Generating CRT Fips Compliant
  *   Make Prime Generation Fips Compliant
*/

/* For FIPS:
 *  Run the AVCP Test (Skip this part right now, deals with making sure the primes are generated correctly.)
 *  Validate the strength of key size
 *  Validate the rng strength
 *  Set the public exponent
 *  Generate the prime factors
 *  Dervie the parameters
 *  Do the pairwise test
*/



int testPrimesBetweenFuncs()
{
  
  BIGNUM* testPrime = BN_secure_new();
  int s = 0, j = 0;
  for(int i = 4; i < 17863; i++)
  {
  BN_set_word(testPrime, i);
  if(miller_rabin_is_prime(testPrime, 64))
    if(BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
      s++;
    else
      j++;
  else
    if(BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
      j++;
  }
  printf("Primes found: %d Discrepancies between other func: %d\n", s, j);
  BN_free(testPrime);
  
  return 0;
}

#define DRNG_NO_SUPPORT 0x0 /* For clarity */
#define DRNG_HAS_RDRAND 0x1
#define DRNG_HAS_RDSEED 0x2


// These don't need to do anything if you don't have anything for them to do.
static void stdlib_rand_cleanup() {}
static int stdlib_rand_add(const void *buf, int num, double add_entropy) {return 0;}
static int stdlib_rand_status() { return 1; }

// Seed the RNG.  srand() takes an unsigned int, so we just use the first
// sizeof(unsigned int) bytes in the buffer to seed the RNG.
static int stdlib_rand_seed(const void *buf, int num)
{
        assert(num >= sizeof(unsigned int));
        srand( *((unsigned int *) buf) );
        return 0;
}

// Fill the buffer with random bytes.  For each byte in the buffer, we generate
// a random number and clamp it to the range of a byte, 0-255.
static int stdlib_rand_bytes(unsigned char *buf, int num)
{
        for( int index = 0; index < num; ++index )
        {
                buf[index] = rand() % 256;
        }
        return 1;
}


// Create the table that will link OpenSSL's rand API to our functions.
RAND_METHOD stdlib_rand_meth = {
        stdlib_rand_seed,
        stdlib_rand_bytes,
        stdlib_rand_cleanup,
        stdlib_rand_add,
        stdlib_rand_bytes,
        stdlib_rand_status
};

// This is a public-scope accessor method for our table.
RAND_METHOD *RAND_stdlib() { return &stdlib_rand_meth; }


int main(int argc, char *argv[]) {


#ifdef LOG_PKEY
BIO_printf(bio_stdout, "Valid key: \n");
printParameter("P", my_key_p);
printParameter("Q", my_key_q);
printParameter("E", my_key_e);
printParameter("D", my_key_d);
printParameter("N", my_key_n);
printParameter("DP", my_key_dp);
printParameter("DQ", my_key_dq);
#endif



#ifdef TEST_PRIMES
BN_set_word(my_key_p, 13);
BN_set_word(my_key_q, 17);
BN_set_word(my_key_e, 7);
#endif
BIGNUM* myE = BN_new();
BN_set_word(myE, 0x100000001);

/* Set the OPENSSL Rng to use our own method. */
RAND_set_rand_method(RAND_stdlib());

/* Make a syscall to /dev/urandom for 4 bytes that can be used to seed the prng */
unsigned char buff[4];
syscall(SYS_getrandom, buff, 4, GRND_NONBLOCK);

RAND_seed(&buff, sizeof(buff));

cRSA *myRsa = new cRSA(kBits, myE, true);


BIGNUM *bnLongRand = BN_secure_new();
BN_rand_ex(bnLongRand, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, BN_CTX_secure_new());
roundTrip(myRsa, (char*)"Test string HeRe! HelLO WoRLd!@#$^&*()_+ 1   2 34    567  89\nTest!");
printf("\n\nTesting long string now.\n\n");
roundTrip(myRsa, (char*)BN_bn2dec(bnLongRand));
_Logger->info("test info!");
return 0;
}