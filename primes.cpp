#include "inc/math/primes.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <stdio.h>

#define RSA_FIPS1864_MIN_KEYGEN_KEYSIZE 2048
#define RSA_FIPS1864_MIN_KEYGEN_STRENGTH 112
int FIPS186_5_MR_ROUNDS_AUX(int nLen);
int FIPS186_5_MR_ROUNDS_PRIME(int nLen);
int FIPS186_5_MIN_AUX(int nLen);
int FIPS186_5_MAX_PROB_LEN(int nLen);

/* Return codes */
#define RET_NOSTATUS -99999
#define RET_FAILURE -1
#define RET_SUCCESS 0

/* 1 / sqrt(2) * 2^256, rounded up */
static const BN_ULONG inv_sqrt_2_val[] = {
    BN_DEF(0x83339916UL, 0xED17AC85UL), BN_DEF(0x893BA84CUL, 0x1D6F60BAUL),
    BN_DEF(0x754ABE9FUL, 0x597D89B3UL), BN_DEF(0xF9DE6484UL, 0xB504F333UL)};

const dataSqrt ossl_bn_inv_sqrt_2 = {
    (BN_ULONG *)inv_sqrt_2_val, OSSL_NELEM(inv_sqrt_2_val),
    OSSL_NELEM(inv_sqrt_2_val), 0, BN_FLG_STATIC_DATA};

/* Using Miller-Rabin */
/* FIPS 186-4 C.3.1 */
/* Returns true for PROBABLY PRIME and false for COMPOSITE */
/* Refactored variable names for FIPS: n->w, s->a, a->b, y->z, m->m */
bool miller_rabin_is_prime(BIGNUM *w, int iterations, BN_CTX *ctx) {
  BIGNUM *w1, *w2, *w4, *m, *b, *x, *z;
  int a = 1;

  /* Confirm odd first */
  if (!BN_is_odd(w))
    return false;

  /* Need to be atleast > 3 else (n-1)=2*/
  if (!(BN_get_word(w) > 3))
    return false;

  /* s > 0 and d odd > 0 such that (n-1) = (2^s)*d # by factoring out powers of
   * 2 from n-1
   * (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)*/
  BN_CTX_start(ctx);
  w1 = BN_CTX_get(ctx);
  w2 = BN_CTX_get(ctx);
  w4 = BN_CTX_get(ctx);
  m = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  x = BN_CTX_get(ctx);
  z = BN_CTX_get(ctx);

  BN_sub(w1, w, BN_value_one());
  BN_sub(w2, w1, BN_value_one());
  BN_sub(w4, w2, BN_value_one());
  BN_sub(w4, w4, BN_value_one());

  /* Calculate s by checking largest number we can divide n-1 by 2^s */
  while (!BN_is_bit_set(w1, a))
    a++;

  /* (n-1)/(2^s) = d */
  BN_rshift(m, w1, a);

  /* Repeat 'k' times where k=iterations */
  for (int i = 0; i < iterations; i++) {
    BN_rand_range(b, w4);
    BN_add(b, b, BN_value_one());
    BN_add(b, b, BN_value_one());
    BN_mod_exp(x, b, m, w, ctx); /* a^m mod n */
                                 /* Repeat 's' times */

    for (int j = 0; j < a; j++) {
      BN_mod_sqr(z, x, w, ctx); /* x^2 mod n */
      if (BN_is_one(z) && !BN_is_one(x) && BN_cmp(x, w1) != 0)
        goto failure;
      BN_copy(x, z); // Previously used x = BN_dup(z) TODO: REMOVE
    }
    if (!BN_is_one(z))
      goto failure;
  }
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return true;

failure:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return false;
}

/* These functions do not support auxiliary primes. */
int probable_prime(BIGNUM *rnd, int bits, prime_t *mods, BN_CTX *ctx) {
  BN_ULONG delta = 0;
  int divisions = 128; /* Divisions for 1024 (OpenSSL) */
  BN_ULONG maxDelta =
      MAXULONGSIZE -
      primes[divisions -
             1]; /* Maximum size of ULONG - the prime index of division for 1024
                    will return 0xFFFFFFFFFFFFFD30 */

/* Using OpenSSL's random bit generator */
/* Constrained to the top two bits being 1 with the number being odd: generates
 * random bits of the given bits size (1024)*/
repeat: /* Used if the rnd number failed */
  delta = 0;
  BN_priv_rand_ex(
      rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0,
      ctx); /* The probability of generating a prime increases with
               leading one's
               https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural
             */

  /* Division test */
  for (int i = 1; i < divisions; i++) {
    BN_ULONG mod =
        BN_mod_word(rnd, (BN_ULONG)primes[i]); /* Random Generated Num / prime
                                                  table up to division (128) */
    mods[i] = (prime_t)mod;
  }
loop:
  for (int i = 1; i < divisions; i++) {
    /* Check that the random number is prime and that the GCD of random-1 and
     * prime index is 1 */
    if (delta <= 0x7fffffff) /* Check that we are within the prime segment */
      if (square(primes[i]) >
          BN_get_word(rnd) + delta) /* Make sure we are within */
        break;

    if ((mods[i] + delta) % primes[i] ==
        0) /* use the remainder + delta and divide by the prime table to check
              if composite*/
    {
      /* Failed, had an even divide by primes */
      /* Increase the delta and retry */
      delta += 2;
      if (delta > maxDelta)
        goto repeat;
      goto loop;
    }
  }
  BN_add_word(
      rnd, delta); /* Add the delta that gave us a prime to our random number */
  if (BN_num_bits(rnd) != bits)
    goto repeat; /* If we didn't generate the correct size then go again. */
  return 0;
}

int generate_prime(BIGNUM *prime, int bits, BN_CTX *ctx = BN_CTX_secure_new()) {
  /* Initialize memory with zeroes and temp vars */
  BIGNUM *temp;
  prime_t *mods = (prime_t *)OPENSSL_zalloc(sizeof(*mods) * NUMPRIMES);
  BN_CTX_start(ctx);
  temp = BN_CTX_get(ctx);
  int checks = FIPS186_5_MR_ROUNDS_PRIME(bits);
  int attempts = 0;
loop:
  /* Generate a random number and set top and bottom bits */
  probable_prime(prime, bits, mods, ctx);
  if (!miller_rabin_is_prime(
          prime,
          checks)) // if( BN_is_prime(prime, checks, NULL, ctx, NULL) == 0 )
    goto loop;
  OPENSSL_free(mods);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return 0;
}

int generatePrimes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits, int testingMR) {
  int primes = 2, quo = 0, rmd = 0, bitsr[2];
  quo = bits / primes;
  rmd = bits % primes;
  BN_CTX *ctx = BN_CTX_secure_new();
  BIGNUM *results[primes], *r1 = BN_CTX_get(ctx), *r2 = BN_CTX_get(ctx);
  if (testingMR) {
    int failed = 0, success = 0;
    BIGNUM *rez[200];
    for (int z = 0; z < 200; z++) {
      rez[z] = BN_CTX_get(ctx);
      generate_prime(rez[z], 1024);
    }

    for (int z = 0; z < 200; z++) {
      miller_rabin_is_prime(rez[z], 1000) ? success++ : failed++;
    }

    for (int z = 0; z < 200; z++) {
      BN_free(rez[z]);
    }
    //printf("\n%d succeeded %d failed.\n", success, failed);
  } else {
    /* Fill the bits array with quotient bit size based on number of primes
     * (Only 2 in this case)*/
    for (int i = 0; i < primes; i++) {
      bitsr[i] = (i < rmd) ? quo + 1 : quo;
      results[i] = BN_CTX_get(ctx);
      for (;;) {
        generate_prime(results[i], bitsr[i]);
        //printf("Testing: %s\n", BN_bn2dec(results[i]));

        BN_sub(r2, results[i], BN_value_one());
        if (BN_mod_inverse(r1, r2, e, BN_CTX_secure_new()) != NULL)
          break;
      }
    }
  }
  //printf("P found: %s\nQ found: %s\n", BN_bn2dec(results[0]),BN_bn2dec(results[1]));
  if (!p && !q) {
    BN_copy(p, results[0]);
    BN_copy(q, results[1]);
  } else {
    p = BN_dup(results[0]);
    q = BN_dup(results[1]);
  }
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

int bn_coprime_test(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
  int ret = 0;
  BIGNUM *tmp;

  BN_CTX_start(ctx);
  tmp = BN_CTX_get(ctx);
  if (tmp == NULL)
    goto end;

  BN_set_flags(a, BN_FLG_CONSTTIME);
  ret = (BN_mod_inverse(tmp, a, b, ctx) != NULL);
end:
  BN_CTX_end(ctx);
  return ret;
}

/* FIPS 186-4-C.9 */
int FIPS186_4_COMPUTE_PROB_PRIME_FROM_AUX(BIGNUM *PRIV_PRIME_FACTOR, BIGNUM *X,
                                          BIGNUM *Xin, BIGNUM *r1, BIGNUM *r2,
                                          int nLen, BIGNUM *e, BN_CTX *ctx) {
  BIGNUM *R, *r1mul2, *r1_mul2_r2, *temp, *tempPrivFactor, *range, *base;
  int bits = nLen >> 1;
  int status = RET_NOSTATUS;

  BN_CTX_start(ctx);
  R = BN_CTX_get(ctx);
  r1mul2 = BN_CTX_get(ctx);
  temp = BN_CTX_get(ctx);
  r1_mul2_r2 = BN_CTX_get(ctx);
  tempPrivFactor = BN_CTX_get(ctx);
  range = BN_CTX_get(ctx);
  base = BN_CTX_get(ctx);
  BN_copy(r1mul2, r1);
  BN_mul_word(r1mul2, 2);
  BN_mul(r1_mul2_r2, r1mul2, r2, ctx);
  BN_gcd(temp, r1mul2, r2, ctx);

  /* Step 1 */
  /* GCD(2r1, r1) != 1 */
  if (BN_cmp(temp, r1mul2) != 0 && BN_cmp(temp, r2) != 0 && !BN_is_one(temp)) {
    LOG_ERROR("{} GCD was not = 1 between the two auxiliary primes", __func__);
    status = RET_FAILURE;
    goto ending;
  }

  /* Step 2*/
  /* R= (( r2^(-1) mod 2r1 ) * r2 ) - (( (2r1)^(-1) mod r2) * 2r1) Applying CRT,
   * so that R=1 (mod2r1) and R = -1(modr2) */

  BN_mod_inverse(R, r2, r1mul2, ctx);
  BN_mul(R, R, r2, ctx);

  BN_mod_inverse(temp, r1mul2, r2, ctx);
  BN_mul(temp, temp, r1mul2, ctx);

  BN_sub(R, R, temp);

  /* If there is a supplied X-Random then use this, else generate one. */
  if (Xin != NULL)
    BN_copy(X, Xin);
  else {
    /* 1 / sqrt(2) * 2^256, rounded up */
    //BIGNUM *sqrt2 = BN_new();
    //BIGNUM *two = BN_new();
    //BIGNUM *twofiftysix = BN_new();
    BIGNUM *sqrt2 = BN_CTX_get(ctx);
    BIGNUM *two   = BN_CTX_get(ctx);
    BIGNUM *twofiftysix = BN_CTX_get(ctx);
    BN_set_word(sqrt2, sqrt(2));
    BN_set_word(two, 2);
    BN_set_word(twofiftysix, 256);
    BN_exp(temp, two, twofiftysix, ctx);  /* 2^256 */
    BN_div(temp, NULL, temp, sqrt2, ctx); /* 2^256 / sqrt(2) */

    //BN_free(sqrt2);
    //BN_free(two);
    //BN_free(twofiftysix);

    if (bits < BN_num_bits(temp)) {
      LOG_ERROR("{} Bits was less than the temp", __func__);
      status = RET_FAILURE;
      goto ending;
    }

    BN_lshift(base, temp, bits - BN_num_bits(temp));
    BN_lshift(range, BN_value_one(), bits);
    BN_sub(range, range, base);
  }

  for (;;) {
    /* Generate X within sqrt(2)(2^(nLen)/(2) - 1) and ( (2^(nLen)/2) - 1) Step
     * 3 */
    if (Xin == NULL) {
      BN_priv_rand_range_ex(X, range, 0, ctx);
      BN_add(X, X, base);
    }

    BN_mod_sub(PRIV_PRIME_FACTOR, R, X, r1_mul2_r2, ctx); /* Step 4 */
    BN_add(PRIV_PRIME_FACTOR, PRIV_PRIME_FACTOR, X);
    int i = 0; /* 5 */
    for (;;) {
      if (BN_num_bits(PRIV_PRIME_FACTOR) > bits) /* Step 6 */
      {
        if (Xin == NULL)
        {
          break; /* Bad X generation so go back to step 3 */
        }
        else
        {
          LOG_ERROR("{} X was already declared.", __func__);
          status = RET_FAILURE;
          goto ending;
          /* X was inputted if we make it here. */
        }
      }

      BN_copy(tempPrivFactor, PRIV_PRIME_FACTOR);
      BN_sub_word(tempPrivFactor, 1);

      if (bn_coprime_test(tempPrivFactor, e, ctx)) /* Step 7 */
      {
        if (miller_rabin_is_prime(PRIV_PRIME_FACTOR,
                                  FIPS186_5_MR_ROUNDS_PRIME(nLen))) {
          status = RET_SUCCESS;
          goto ending;
        }
      }

      i++;                   /* Step 8 */
      if (i >= 5 * nLen / 2) /* Step 9 */
      {
        LOG_ERROR("{} I was >= 5*nlen/2", __func__);
        status = RET_FAILURE;
        goto ending;
      }
      BN_add(PRIV_PRIME_FACTOR, PRIV_PRIME_FACTOR, r1_mul2_r2); /* Step 10 */
    }
  }
ending:
  BN_CTX_end(ctx);
  return status;
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_FIND_AUX_PRIME(const BIGNUM *Xn1, BIGNUM *n1, int kbits,
                             BN_CTX *ctx) {
  int status = RET_NOSTATUS;
  /* Start from Xn1 and find the FIRST integer that is a probable prime then
   * return it. */
  BN_copy(n1, Xn1); /* Changed to copy to prevent mem leak */

  BN_set_flags(n1, BN_FLG_CONSTTIME);
  for (;;) {

    if (miller_rabin_is_prime(n1, FIPS186_5_MR_ROUNDS_AUX(kbits))) {
      status = RET_SUCCESS;
      break;
    } else
      BN_add_word(n1, 2);
  }
  return status;
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_GEN_PROB_PRIME(BIGNUM *p, BIGNUM *Xpout, BIGNUM *p1, BIGNUM *p2,
                             BIGNUM *Xp, BIGNUM *Xp1, BIGNUM *Xp2, BIGNUM *e,
                             int nlen, bool testParamsFilled, BN_CTX *ctx) {
  int status = RET_NOSTATUS;
  BIGNUM *p1i = NULL, *p2i = NULL, *xp1i = NULL, *xp2i = NULL;

  BN_CTX_start(ctx);

  if (p1 == NULL)
    p1i = BN_CTX_get(ctx);
  else
    p1i = p1;

  if (p2 == NULL)
    p2i = BN_CTX_get(ctx);
  else
    p2i = p2;

  if (Xp1 == NULL)
    xp1i = BN_CTX_get(ctx);
  else
    xp1i = Xp1;

  if (Xp2 == NULL)
    xp2i = BN_CTX_get(ctx);
  else
    xp2i = Xp2;

  /* If this is a test, skip generation else will proceed to generate Xn1 and
   * Xn2 */
  if (Xp1 == NULL) {
    BN_priv_rand_ex(xp1i, FIPS186_5_MIN_AUX(nlen), BN_RAND_TOP_ONE,
                    BN_RAND_BOTTOM_ODD, 0, ctx);
  }

  if (Xp2 == NULL) {
    BN_priv_rand_ex(xp2i, FIPS186_5_MIN_AUX(nlen), BN_RAND_TOP_ONE,
                    BN_RAND_BOTTOM_ODD, 0, ctx);
  }

  /* Generate the auxilary primes now */
  FIPS186_4_FIND_AUX_PRIME(xp1i, p1i, nlen, ctx);
  FIPS186_4_FIND_AUX_PRIME(xp2i, p2i, nlen, ctx);

  /* Make sure the auxilary primes' sum are within the max length */
  if ((BN_num_bits(p1i) + BN_num_bits(p2i)) >= FIPS186_5_MAX_PROB_LEN(nlen)) {
    LOG_ERROR("{} Auxiliary primes sum was not within the maximum length", __func__);
    status = RET_FAILURE;
    goto ending;
  }

  /* Finally generate the prime using the auxilary primes */
  if (RET_SUCCESS == FIPS186_4_COMPUTE_PROB_PRIME_FROM_AUX(p, Xpout, Xp, p1i,
                                                           p2i, nlen, e, ctx))
    status = RET_SUCCESS;
  else
    status = RET_FAILURE;

ending:
  BN_CTX_end(ctx);
  return status;
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_PRIME_EQUALITY_CHECK(BIGNUM *diff, const BIGNUM *p,
                                   const BIGNUM *q, int nbits) {
  int bitlen = (nbits >> 1) - 100;

  if (!BN_sub(diff, p, q))
    return -1;
  BN_set_negative(diff, 0);

  if (BN_is_zero(diff))
    return 0;

  if (!BN_sub_word(diff, 1))
    return -1;
  return (BN_num_bits(diff) > bitlen);
}

/* FIPS 186-4-B.3.6 */
int FIPS186_4_GEN_PRIMES(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits, bool doACVP,
                         ACVP_TEST *testParams) {
  BIGNUM *Xpo = NULL, *Xqo = NULL, *tmp = NULL, *p1 = NULL, *p2 = NULL,
         *q1 = NULL, *q2 = NULL, *Xpout = NULL, *Xqout = NULL, *Xp = NULL,
         *Xp1 = NULL, *Xp2 = NULL, *Xq = NULL, *Xq1 = NULL, *Xq2 = NULL;
  BN_CTX *ctx = BN_CTX_secure_new();

  if (doACVP) {
    Xp1 = testParams->Xp1;
    Xp2 = testParams->Xp2;
    Xp = testParams->Xp;
    p1 = testParams->p1;
    p2 = testParams->p2;

    Xq1 = testParams->Xq1;
    Xq2 = testParams->Xq2;
    Xq = testParams->Xq;
    q1 = testParams->q1;
    q2 = testParams->q2;
  }

  BN_CTX_start(ctx);
  tmp = BN_CTX_get(ctx);

  if (Xpout == NULL)
    Xpo = BN_CTX_get(ctx);
  else
    Xpo = Xpout;

  if (Xqout == NULL)
    Xqo = BN_CTX_get(ctx);
  else
    Xqo = Xqout;

  BN_set_flags(Xpo, BN_FLG_CONSTTIME);
  BN_set_flags(Xqo, BN_FLG_CONSTTIME);
  BN_set_flags(p, BN_FLG_CONSTTIME);
  BN_set_flags(q, BN_FLG_CONSTTIME);

  FIPS186_4_GEN_PROB_PRIME(p, Xpo, p1, p2, Xp, Xp1, Xp2, e, bits, doACVP, ctx);
  for (;;) {
    /* Generate the primes */
    FIPS186_4_GEN_PROB_PRIME(q, Xqo, q1, q2, Xq, Xq1, Xq2, e, bits, doACVP,
                             ctx);

    if (FIPS186_4_PRIME_EQUALITY_CHECK(tmp, Xpo, Xqo, bits) == 0)
      continue;
    if (FIPS186_4_PRIME_EQUALITY_CHECK(tmp, p, q, bits) == 0)
      continue;
    break;
  }

#ifdef LOG_PRIME_GEN_B_3_6
   //TODO FIX THIS
  //std::string pHex = BN_bn2hex(p);
  //std::string qHex = BN_bn2hex(q);
  //printf("Found:\nP: %s\nQ: %s\n", pHex.c_str(), qHex.c_str());
#endif

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

/* Probable prime generation is within FIPS 186-4.C.7 */

/* Can return Xpout (the returned random number for generation of P)
 * Can return Xqout (the returned random number for generation of Q)
 * Can input Xp, Xg (the random numbers used during generatino of p,q)
 * Can input Xp1, Xp2 (the random numbers which will generate the auxiliary
 * primes)
 */

/* Minimum rounds of M-R testing from 186-5-B-1 */
/* 2^-100 error probability */
int FIPS186_5_MR_ROUNDS_AUX(int nLen) {
  if (nLen >= 1024)
    return 32;
  else if (nLen >= 1536)
    return 27;
  else if (nLen >= 2048)
    return 22;
  else
    return -1;
}

/* Minimum rounds of M-R testing from 186-5-B-1 */
int FIPS186_5_MR_ROUNDS_PRIME(int nLen) {
  if (nLen >= 1024)
    return 4;
  else if (nLen >= 1536)
    return 3;
  else if (nLen >= 2048)
    return 2;
  else
    return -1;
}

/* Minimum length of an auxilary prime from FIPS 186-5-A.1 */
int FIPS186_5_MIN_AUX(int nLen) {
  if (nLen <= 3071)
    return 140;
  else if (nLen <= 4095)
    return 170;
  else if (nLen >= 4096)
    return 200;
  else
    return -1;
}

/*Maximum size of probable prime bitlength(p1+p2) from FIPS 186-5-A.1 */
int FIPS186_5_MAX_PROB_LEN(int nLen) {
  if (nLen <= 3071)
    return 1007;
  else if (nLen <= 4095)
    return 1518;
  else if (nLen >= 4096)
    return 2030;
  else
    return -1;
}
