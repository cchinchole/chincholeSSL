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


struct RSA_Params {
  BIGNUM *p, *q, *e, *n = BN_new(), *d = BN_new(), *dp = BN_new(), *dq = BN_new(), *qInv = BN_new();
};

class Timer {
  private:
    std::chrono::_V2::high_resolution_clock::time_point startp;
    std::chrono::_V2::high_resolution_clock::time_point endp;
  public:
    void start()
    {
      startp = std::chrono::high_resolution_clock::now();
    }

    void stop()
    {
      endp = std::chrono::high_resolution_clock::now();
    }
    
    unsigned int getElapsed(bool useStop = false)
    {
      if(useStop)
        stop();
      return std::chrono::duration_cast<std::chrono::microseconds>(endp - startp).count();
    }
};

int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx = BN_CTX_new());
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx = BN_CTX_new());
int rsa_roundtrip(std::string msg, RSA_Params* rsa);
int printParameter(std::string param_name, BIGNUM* num);
Timer t;

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
int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx)
{
  
  BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;
  
  BN_CTX_start(ctx);
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  lcm = BN_CTX_get(ctx);
  p1q1 = BN_CTX_get(ctx);
  gcd = BN_CTX_get(ctx);

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