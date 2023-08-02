
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
#include "inc/crypto/rsa.hpp"
#include "inc/defs.hpp"
#include "inc/utils/logger.hpp"
#include "inc/math/primes.hpp"
#include "inc/utils/time.hpp"


/* Make sure that k = (k^e)^d mod n ; for some int k where 1 < k < n-1 */
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx)
{
  BIGNUM* k, *tmp;
  BN_CTX_start(ctx);
  k = BN_CTX_get(ctx);
  tmp = BN_CTX_get(ctx);

  /* First set k to 2 (between 1 < n-1 ) then take ( k^e mod n )^d mod n and compare k to tmp */
  int ret = ( BN_set_word(k, 2) && BN_mod_exp(tmp, k, rsa->e, rsa->n, ctx) && BN_mod_exp(tmp, tmp, rsa->d, rsa->n, ctx) && !BN_cmp(k, tmp) );
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}

 /*
  * Key Pair:
  * <d, n>: Form the private decryption key.
  * <e, n>: Form the public encryption key.
  * 
  * Chinese Remainder Theorem Params:        
  * <p, q, dP, dQ, qInv>: Form the quintuple private key used for decryption.
  * CRT and Euler's Theorem are used here.
  * https://www.di-mgt.com.au/crt_rsa.html
  * https://math.berkeley.edu/~charles/55/2-21.pdf
  * Benefit of using RSA-CRT over RSA is to speed up the decryption time.
  */

/* Computes d, n, dP, dQ, qInv from the prime factors and public exponent */
int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx, bool constTime)
{
  /* FIPS requires the bit length to be within 17-256 */
  if(!(BN_is_odd(rsa->e) && BN_num_bits(rsa->e) > 16 && BN_num_bits(rsa->e) < 257))
  {
    return -1; 
  }

  
  Timer t;
  BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;
  
  BN_CTX_start(ctx);
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  lcm = BN_CTX_get(ctx);
  p1q1 = BN_CTX_get(ctx);
  gcd = BN_CTX_get(ctx);

  if(constTime)
  {
    BN_set_flags(p1, BN_FLG_CONSTTIME);
    BN_set_flags(q1, BN_FLG_CONSTTIME);
    BN_set_flags(lcm, BN_FLG_CONSTTIME);
    BN_set_flags(p1q1, BN_FLG_CONSTTIME);
    BN_set_flags(gcd, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->d, BN_FLG_CONSTTIME);
    /* Note: N is not required to be constant time. */
    BN_set_flags(rsa->dp, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->dq, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->qInv, BN_FLG_CONSTTIME);
  }

  _Logger->parameter("P", rsa->p);
  _Logger->parameter("Q", rsa->q);
  _Logger->parameter("E", rsa->e);

  /* Step 1: Find the least common multiple of (p-1, q-1) */
  BN_sub(p1, rsa->p, BN_value_one());  /* p - 1 */
  BN_sub(q1, rsa->q, BN_value_one());  /* q - 1 */
  BN_mul(p1q1, p1, q1, ctx);      /* (p-1)(q-1)*/
  BN_gcd(gcd, p1, q1, ctx);       
  BN_div(lcm, NULL, p1q1, gcd, ctx);

  _Logger->parameter("GCD", gcd);
  _Logger->parameter("LCM", lcm);

  /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
  /* Keep repeating incase the bitsize is too short */
 

  /* Not compliant since will show D failures if the loop continues. Need to finish function and return a value to show failure to restart. */
  for(;;)
  {
      BN_mod_inverse(rsa->d, rsa->e, lcm, ctx);
      _Logger->parameter("D", rsa->d);
      #ifdef DO_CHECKS
        if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
          break;
      #else
        break;
      #endif
  }

  /* Step 3: n = pq */
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  _Logger->parameter("N", rsa->n);

  t.start();
  /* Step 4: dP = d mod(p-1)*/
  BN_mod(rsa->dp, rsa->d, p1, ctx);

  /* Step 5: dQ = d mod(q-1)*/
  BN_mod(rsa->dq, rsa->d, q1, ctx);

  /* Step 6: qInv = q^(-1) mod(p) */
  BN_mod_inverse(rsa->qInv, rsa->q, rsa->p, ctx);

  printf("Took: %dms to generate CRT parameters.\n", t.getElapsed(true));

  _Logger->parameter("DP", rsa->dp);
  _Logger->parameter("DQ", rsa->dq);
  _Logger->parameter("QINV", rsa->qInv);

  if(rsa_sp800_56b_pairwise_test(rsa))
    printf("Pairwise passed!\n");
  else
    printf("Pairwise failed!\n");

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

cRSAKey::cRSAKey(int bits, BIGNUM *eGiven, bool auxMode, BN_CTX* ctx)
{
  params = new RSA_Params();

  BIGNUM *p1 = nullptr, *q1 = nullptr, *lcm = nullptr, *p1q1 = nullptr, *gcd = nullptr;
  this->params->p = BN_secure_new();
  this->params->q = BN_secure_new();

  if(eGiven == NULL)
  {
    this->params->e = BN_new();
    BN_set_word(this->params->e, 65537);
  }
  else
    this->params->e = BN_dup(eGiven);

  this->params->n = BN_secure_new();
  this->params->d = BN_secure_new();
  this->params->dp = BN_secure_new();
  this->params->dq = BN_secure_new();
  this->params->qInv = BN_secure_new();
  this->kBits = bits;

   
  if(auxMode)
  {
    ACVP_TEST test = {
           NULL, NULL,        /* XP Out, XQ Out */
           NULL, NULL, NULL,  /* XP, XP1, XP2*/
           NULL, NULL, NULL,  /* XQ, XQ1, XQ2 */
           NULL, NULL,        /* P1, P2 */
           NULL, NULL,        /* Q1, Q2 */
    };

    FIPS186_4_GEN_PRIMES( this->params->p, this->params->q, this->params->e, kBits, true, &test);
    gen_rsa_sp800_56b(this->params, kBits);
  } 
  else
  {
    generatePrimes(this->params->p, this->params->q, this->params->e,  kBits, 0);
    gen_rsa_sp800_56b(this->params, kBits);
  }
  
}

unsigned char* cRSAKey::encrypt(unsigned int *out_len, char *src, BN_CTX *ctx)
{ 
  unsigned int numBytes = strlen(src)-1;
  unsigned int maxBytes = (kBits/8);
  unsigned int numPages = (numBytes/maxBytes);
  unsigned char* returnData = (unsigned char*)malloc((numPages+1)*maxBytes);
  unsigned int returnPtr = 0;
  
  for(int i = 0; i <= numPages; i++)
  {
      BN_CTX_start(ctx);

      /* Convert the src buffer into a bignumber to be used for encryption */
      BIGNUM *originalNumber = BN_CTX_get(ctx);
      BN_bin2bn( (unsigned char*)src + (i*maxBytes), maxBytes, originalNumber);
      #ifdef LOG_CRYPTO
      std::cout << "Original Number: " << BN_bn2dec(originalNumber) <<std::endl;
      #endif
      /* Encrypt the data */
      BIGNUM *cipherNumber  = BN_CTX_get(ctx);
      BN_mod_exp(cipherNumber, originalNumber, this->params->e, this->params->n, ctx);
      #ifdef LOG_CRYPTO
      std::cout << "Encrypted Number: " << BN_bn2dec(cipherNumber) << std::endl <<std::endl;
      #endif

      /* Convert big number to binary */
      unsigned char *dataBuffer = (unsigned char*)malloc(maxBytes);
      BN_bn2bin(cipherNumber, dataBuffer);
      memcpy(returnData + (returnPtr), dataBuffer, BN_num_bytes(cipherNumber));
      
      /* Incremement the pointer and add to the output length*/
      returnPtr += BN_num_bytes(cipherNumber);
      *out_len = returnPtr;
      free(dataBuffer);
      BN_CTX_end(ctx);
  }
  BN_CTX_free(ctx);

  return returnData;
}

std::string cRSAKey::decrypt(unsigned char *cipher, unsigned int cipher_length, BN_CTX *ctx, bool crt)
{
      unsigned int maxBytes = (kBits/8);
      unsigned int numPages = (cipher_length/(maxBytes));
      std::string returnData;

      for(int i = 0; i < numPages;i++)
      {
        BN_CTX_start(ctx);
        BIGNUM* cipherNumber = BN_CTX_get(ctx);
        BIGNUM* decryptedData = BN_CTX_get(ctx);

        /* Convert */
        BN_bin2bn(cipher + (i*maxBytes), maxBytes , cipherNumber);
        
        /* Perform CRT Decryption */
        if(crt)
        { 
          BIGNUM *m1 = BN_CTX_get(ctx);
          BIGNUM *m2 = BN_CTX_get(ctx);
          BIGNUM *h = BN_CTX_get(ctx);
          BIGNUM *m1subm2 = BN_CTX_get(ctx);
          BIGNUM *hq = BN_CTX_get(ctx);

          /* m1 = c^(dP) mod p */
          BN_mod_exp(m1, cipherNumber, this->params->dp, this->params->p, ctx);
          
          /* m2 = c^(dQ) mod q */
          BN_mod_exp(m2, cipherNumber, this->params->dq, this->params->q, ctx);
          
          /* m1subm2 = (m1-m2) */
          BN_sub(m1subm2, m1, m2);
          
          /* h = qInv*(m1subm2) mod p */
          BN_mod_mul(h, this->params->qInv, m1subm2, this->params->p, ctx);
          
          /* hq = h*q */
          BN_mul(hq, h, this->params->q, ctx);
          
          /* m = m2+h*q */
          BN_add(decryptedData, m2, hq);
        }
        else
          (decryptedData, cipherNumber, this->params->d, this->params->n, ctx);

        #ifdef LOG_CRYPTO
          std::cout << "Decrypted Numbers: " << BN_bn2dec(decryptedData) <<std::endl<<std::endl<<std::endl;
        #endif
        unsigned char* dataBuffer = (unsigned char*)malloc(BN_num_bytes(decryptedData));
        BN_bn2bin(decryptedData, (unsigned char*)dataBuffer);
        returnData.append((char*)dataBuffer);
        
        free(dataBuffer);
        BN_CTX_end(ctx);
      }
    
    BN_CTX_free(ctx);
    return returnData;
}

int roundTrip(cRSAKey* rsa, char* str)
{
  unsigned int out_len = 0;
  unsigned char* cipher = rsa->encrypt(&out_len, str);
  std::string out = (rsa->decrypt(cipher, out_len));
  int strresult = strcmp( (char*)str, (char*)out.c_str());
  #ifdef LOG_CRYPTO
  std::cout << "- - - - - - - - Encryption Decryption self test - - - - - - - -" << std::endl << "The inputted string: " << str << std::endl << "The outputted string: " << out << std::endl << "STRCMP returned " << strresult << std::endl << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" << std::endl;
  #endif
  return 0;
}

/*  BN_CTX:
 *    Description:
 *     Holds BigNum temporary variables that will be used by library functions.
 *     Solves the issue of expensive use with repeated subroutine calls where dynamic memory allocation is used
 *    
 *    BN_CTX_new_ex():
 *     Creates and initializes a new structure for the given library context, if left null will use the default library context
 *  
 *    BN_CTX_new():
 *     Performs the same as BN_CTX_new_ex() except it will always use the default library.
 *
 *    BN_CTX_secure_new_ex():
 *      Uses the secure heap to hold big numbers.
 *
 *    BN_CTX_start():
 *      Required to obtain IBGNUMS from the context and is ended with BN_CTX_end()
 * 
 *    BN_CTX_free():
 *      Frees the components and structure itself, call BN_CTX_end() first.
 * 
 *    Can only use a BN_CTX within a single thread of execution.
 */

/*
 * https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural :: Why there are leading ones in rng generation
 * https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html :: CRT
 * https://mathstats.uncg.edu/sites/pauli/112/HTML/seceratosthenes.html :: Sieve of Eratosthenes
 * http://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html :: RSA
 * https://www.di-mgt.com.au/crt_rsa.html :: CRT encryption
 * https://security.stackexchange.com/questions/176394/how-does-openssl-generate-a-big-prime-number-so-fast :: OpenSSL Generating prime numbers
 */