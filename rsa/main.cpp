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
#include "inc/defs.hpp"
#include "inc/primes.hpp"


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


RSA_Params myRsaParams = {
  BN_secure_new(), BN_secure_new(), BN_secure_new(), BN_secure_new(), BN_secure_new(), BN_secure_new(), BN_secure_new(), BN_secure_new()
};

RSA_Params* rsaPtr = &myRsaParams;
rsaPtr->e = BN_dup(my_key_e);

Timer t;

t.start();
miller_rabin_is_prime(rsaPtr->p, 64);
t.stop();
printf("\nMiller Rabin by me time took %dns", t.getElapsed(false, 1));
t.start();
BN_check_prime(rsaPtr->p, BN_CTX_secure_new(), NULL);
t.stop();
printf("\nMiller Rabin by SSL time took %dns", t.getElapsed(false, 1));


generatePrimes(rsaPtr, kBits);

#ifdef TEST_PRIMES
BN_set_word(my_key_p, 13);
BN_set_word(my_key_q, 17);
BN_set_word(my_key_e, 7);
#endif

cRSA *myRsa = new cRSA(kBits, rsaPtr->p, rsaPtr->q, rsaPtr->e);

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