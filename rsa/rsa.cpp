
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


int printParameter(std::string param_name, BIGNUM* num)
{
  #ifdef LOG_PARAMS
  BIO_printf(bio_stdout, "%-5s", param_name.c_str());
  BIO_printf(bio_stdout, "%s", BN_bn2dec(num));
  BIO_printf(bio_stdout, "\n");
  #endif
  return 0;
}



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
  generatePrimes(rsa, nBits, 0);
  
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

  printParameter("P", rsa->p);
  printParameter("Q", rsa->q);
  printParameter("E", rsa->e);

  /* Step 1: Find the least common multiple of (p-1, q-1) */
  BN_sub(p1, rsa->p, BN_value_one());  /* p - 1 */
  BN_sub(q1, rsa->q, BN_value_one());  /* q - 1 */
  BN_mul(p1q1, p1, q1, ctx);      /* (p-1)(q-1)*/
  BN_gcd(gcd, p1, q1, ctx);       
  BN_div(lcm, NULL, p1q1, gcd, ctx);

  printParameter("GCD", gcd);
  printParameter("LCM", lcm);

  /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
  /* Keep repeating incase the bitsize is too short */
 

  /* Not compliant since will show D failures if the loop continues. Need to finish function and return a value to show failure to restart. */
  for(;;)
  {
      BN_mod_inverse(rsa->d, rsa->e, lcm, ctx);
      printParameter("D", rsa->d);
      #ifdef DO_CHECKS
        if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
          break;
      #else
        break;
      #endif
  }

  /* Step 3: n = pq */
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  printParameter("N", rsa->n);

  t.start();
  /* Step 4: dP = d mod(p-1)*/
  BN_mod(rsa->dp, rsa->d, p1, ctx);

  /* Step 5: dQ = d mod(q-1)*/
  BN_mod(rsa->dq, rsa->d, q1, ctx);

  /* Step 6: qInv = q^(-1) mod(p) */
  BN_mod_inverse(rsa->qInv, rsa->q, rsa->p, ctx);

  printf("Took: %dms to generate CRT parameters.\n", t.getElapsed(true));

  printParameter("DP", rsa->dp);
  printParameter("DQ", rsa->dq);
  printParameter("QINV", rsa->qInv);

  if(rsa_sp800_56b_pairwise_test(rsa))
    printf("Pairwise passed!\n");
  else
    printf("Pairwise failed!\n");

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
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