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
#include "inc/rand.hpp"
#include "inc/hash/sha.hpp"
#include "inc/test.hpp"

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




int main(int argc, char *argv[]) {
  BIGNUM* myE = BN_new();
  BN_set_word(myE, 0x100000001);

  /* Set the OPENSSL Rng to use our own method. */
  /* This is deprecated needs updated */
  RAND_set_rand_method(RAND_stdlib());

  /* Make a syscall to /dev/urandom for 4 bytes that can be used to seed the prng */
  unsigned char buff[4];
  syscall(SYS_getrandom, buff, 4, GRND_NONBLOCK);

  RAND_seed(&buff, sizeof(buff));

  cRSA *myRsa = new cRSA(kBits, myE, true);


  BIGNUM *bnLongRand = BN_secure_new();
  BN_rand_ex(bnLongRand, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, BN_CTX_secure_new());
  unsigned char* testBytes = (unsigned char*)malloc(32*sizeof(char));
  RAND_bytes(testBytes, 32);
  roundTrip(myRsa, (char*)"Test string HeRe! HelLO WoRLd!@#$^&*()_+ 1   2 34    567  89\nTest!");
  printf("\n\nTesting long string now.\n\n");
  roundTrip(myRsa, (char*)BN_bn2dec(bnLongRand));


  testSHA_1("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D");
  testSHA_1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
  testSHA_2("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909");
  return 0;
}