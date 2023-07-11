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
#include "inc/defs.hpp"
#include "inc/primes.hpp"
#include "inc/test.hpp"
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <openssl/rand.h>

const int kBits = 2048;
int keylen;
char *pem_key;
BIO *bio_stdout;

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

int roundTrip(cRSA* rsa, char* str)
{
  unsigned int out_len = 0;
  unsigned char* cipher = rsa->encrypt(&out_len, str);
  std::string out = (rsa->decrypt(cipher, out_len));
  int strresult = strcmp( (char*)str, (char*)out.c_str());
  std::cout << "- - - - - - - - Encryption Decryption self test - - - - - - - -" << std::endl << "The inputted string: " << str << std::endl << "The outputted string: " << out << std::endl << "STRCMP returned " << strresult << std::endl << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" << std::endl;
  return 0;
}

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
/* Setup the openssl basic io output*/
bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

/* Generate RSA Key */
EVP_PKEY* pKey = EVP_RSA_gen(kBits);

BIO *bio = BIO_new(BIO_s_mem());
PEM_write_bio_PrivateKey(bio, pKey, NULL, NULL, 0, 0, NULL);
keylen = BIO_pending(bio);
pem_key = (char*)calloc(keylen+1, 1); // Null-terminate
BIO_read(bio, pem_key, keylen);
BIO_printf(bio_stdout, "%s\n\n\n", pem_key);

BIGNUM *my_key_p = nullptr, *my_key_q = nullptr, *my_key_d = nullptr, *my_key_e = nullptr, *my_key_n = nullptr, *my_key_dp = nullptr, *my_key_dq = nullptr;

EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_FACTOR1, &my_key_p);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_FACTOR2, &my_key_q);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_D, &my_key_d);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &my_key_e);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &my_key_n);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &my_key_dp);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &my_key_dq);

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


RSA_Params myRsaParams = {};

RSA_Params* rsaPtr = &myRsaParams;


#ifdef TEST_PRIMES
BN_set_word(my_key_p, 13);
BN_set_word(my_key_q, 17);
BN_set_word(my_key_e, 7);
#endif

BN_set_word(my_key_e, 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001);
rsaPtr->e = BN_dup(my_key_e);
rsaPtr->p = BN_new();
rsaPtr->q = BN_new();


ACVP_TEST test = {
           NULL, NULL,        /* XP Out, XQ Out */
           NULL, NULL, NULL,  /* XP, XP1, XP2*/
           NULL, NULL, NULL,  /* XQ, XQ1, XQ2 */
           NULL, NULL,        /* P1, P2 */
           NULL, NULL,        /* Q1, Q2 */
};



RAND_set_rand_method(RAND_stdlib());
BIGNUM* seed = BN_new();
BN_hex2bn(&seed, "e5f707e49c4e7cc8fb202b5cd957963713f1c4726677c09b6a7f5dfe");
RAND_seed(&seed, sizeof(seed));

cRSA *myRsa = new cRSA(kBits, NULL);
FIPS186_4_GEN_PRIMES( (myRsa->params), kBits, true, &test);
gen_rsa_sp800_56b(myRsa->params, kBits);


BIGNUM *bnLongRand = BN_secure_new();
BN_rand_ex(bnLongRand, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, BN_CTX_secure_new());
roundTrip(myRsa, (char*)"Test string HeRe! HelLO WoRLd!@#$^&*()_+ 1   2 34    567  89\nTest!");
printf("\n\nTesting long string now.\n\n");
roundTrip(myRsa, (char*)BN_bn2dec(bnLongRand));



BIO_free_all(bio_stdout);
BIO_free_all(bio);

BN_free( my_key_p );
BN_free( my_key_q );
BN_free( my_key_d );
BN_free( my_key_e );
BN_free( my_key_n );
BN_free( my_key_dp );
BN_free( my_key_dq );
free(pKey);
delete pem_key;
return 0;
}